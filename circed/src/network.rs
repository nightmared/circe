use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::rc::Rc;

use nasty_network_ioctls::{
    add_interface_to_bridge, create_bridge, create_tap, interface_id, interface_set_ip,
    interface_set_up, set_alias_to_interface,
};
use nix::errno::Errno;
use rustables::expr::{
    Bitwise, Cmp, CmpOp, Conntrack, Counter, Immediate, Ipv4HeaderField, Meta, Nat, NatType,
    NetworkHeaderField, Payload, Register, States, TcpHeaderField, TransportHeaderField,
};
use rustables::{Batch, Chain, ProtoFamily, Rule, RuleMethods, Table};
use tracing::error;

use crate::ruleset::VirtualRuleset;
use crate::Error;
use circe_common::{Challenge, Config};

lazy_static::lazy_static! {
    static ref FILTER_TABLE_NAME: CString = CString::new("filter").unwrap();
    static ref INPUT_CHAIN_NAME: CString = CString::new("input").unwrap();
    static ref OUTPUT_CHAIN_NAME: CString = CString::new("output").unwrap();
    static ref FORWARD_CHAIN_NAME: CString = CString::new("forward").unwrap();
    static ref NAT_TABLE_NAME: CString = CString::new("nat").unwrap();
    static ref PREROUTING_CHAIN_NAME: CString = CString::new("prerouting").unwrap();
}

fn get_or_create_rule(
    ruleset: &mut VirtualRuleset,
    family: ProtoFamily,
    table_name: impl AsRef<CStr>,
    cb_table: impl Fn(&mut Table) -> Result<(), Error>,
    chain_name: impl AsRef<CStr>,
    cb_chain: impl Fn(&mut Chain) -> Result<(), Error>,
    cb_rule: impl Fn(Rule) -> Result<Rule, Error>,
) -> Result<(), Error> {
    let table = match ruleset.get_table(table_name.as_ref(), family) {
        Some(v) => v,
        None => {
            let mut table = Table::new(&table_name.as_ref(), family);

            cb_table(&mut table)?;

            ruleset.add_table(Rc::new(table))?
        }
    };

    let chain = match table.get_chain(chain_name.as_ref()) {
        Some(v) => v,
        None => {
            let mut chain = Chain::new(&chain_name.as_ref(), table.table.clone());

            cb_chain(&mut chain)?;

            table.add_chain(Rc::new(chain))?
        }
    };

    let rule = cb_rule(Rule::new(chain.chain.clone()))?;

    if let Err(e) = chain.add_rule(Rc::new(rule)) {
        match e {
            Error::AlreadyExistsError => {}
            _ => return Err(e),
        }
    }

    Ok(())
}

fn allow_containers_to_phone_home(
    ruleset: &mut VirtualRuleset,
    conf: &Config,
    interfaces: Vec<(String, Ipv4Addr)>,
) -> Result<(), Error> {
    for (interface_name, interface_ip) in interfaces {
        get_or_create_rule(
            ruleset,
            ProtoFamily::Ipv4,
            FILTER_TABLE_NAME.as_ref(),
            |_table| Ok(()),
            OUTPUT_CHAIN_NAME.as_ref(),
            |_chain| Ok(()),
            |mut rule| {
                let mut name_arr = [0u8; libc::IFNAMSIZ];
                for (pos, i) in interface_name.bytes().enumerate() {
                    name_arr[pos] = i;
                }
                rule.add_expr(&Meta::IifName);
                rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
                rule.add_expr(&Meta::L4Proto);
                rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
                rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
                    TcpHeaderField::Dport,
                )));
                rule.add_expr(&Cmp::new(CmpOp::Eq, conf.listening_port.to_be()));
                rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
                    Ipv4HeaderField::Daddr,
                )));
                rule.add_expr(&Cmp::new(CmpOp::Eq, conf.network.ip()));
                rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
                    Ipv4HeaderField::Saddr,
                )));
                rule.add_expr(&Cmp::new(CmpOp::Eq, interface_ip));
                Ok(rule.accept())
            },
        )?;
        // allow established/related packets
        get_or_create_rule(
            ruleset,
            ProtoFamily::Ipv4,
            FILTER_TABLE_NAME.as_ref(),
            |_table| Ok(()),
            OUTPUT_CHAIN_NAME.as_ref(),
            |_chain| Ok(()),
            |mut rule| {
                let mut name_arr = [0u8; libc::IFNAMSIZ];
                for (pos, i) in interface_name.bytes().enumerate() {
                    name_arr[pos] = i;
                }
                rule.add_expr(&Meta::IifName);
                rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
                rule.add_expr(&Meta::L4Proto);
                rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
                rule.add_expr(&Conntrack::State);
                let allowed_states = (States::ESTABLISHED | States::RELATED).bits();
                rule.add_expr(&Bitwise::new(allowed_states, 0u32));
                rule.add_expr(&Cmp::new(CmpOp::Neq, 0u32));
                Ok(rule.accept())
            },
        )?;
    }

    Ok(())
}

fn create_port_forwarding(ruleset: &mut VirtualRuleset, chall: &Challenge) -> Result<(), Error> {
    get_or_create_rule(
        ruleset,
        ProtoFamily::Ipv4,
        NAT_TABLE_NAME.as_ref(),
        |_table| Ok(()),
        PREROUTING_CHAIN_NAME.as_ref(),
        |chain| {
            chain.set_type(rustables::ChainType::Nat);
            chain.set_hook(rustables::Hook::PreRouting, -100i32);
            Ok(())
        },
        |mut rule| {
            rule.add_expr(&Meta::L4Proto);
            // L4Proto returns a single byte
            rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
            rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
                TcpHeaderField::Dport,
            )));
            rule.add_expr(&Cmp::new(CmpOp::Eq, chall.source_port.to_be()));
            rule.add_expr(&Immediate::new(chall.container_ip.octets(), Register::Reg1));
            rule.add_expr(&Immediate::new(chall.destination_port, Register::Reg2));
            rule.add_expr(&Counter {
                nb_bytes: 0,
                nb_packets: 0,
            });
            rule.add_expr(&Nat {
                nat_type: NatType::DNat,
                family: ProtoFamily::Ipv4,
                ip_register: Register::Reg1,
                port_register: Some(Register::Reg2),
            });
            Ok(rule)
        },
    )
}

pub fn setup_nat(conf: &Config, interfaces: Vec<(String, Ipv4Addr)>) -> Result<(), Error> {
    let userdata = CString::new(conf.bridge_name.as_str())?;
    let mut ruleset = VirtualRuleset::new(userdata.clone())?;
    ruleset.reload_state_from_system()?;

    // atomic nftables configuration
    let mut batch = Batch::new();
    ruleset.delete_overlay(&mut batch)?;

    let mut ruleset = VirtualRuleset::new(userdata)?;
    for chall in &conf.challenges {
        if !conf.network.contains(chall.container_ip) {
            error!(
                "The configuration of challenge '{:?}' contains an invalid IP (out of the target network)",
                chall
            );
            continue;
        }
        create_port_forwarding(&mut ruleset, chall)?;
    }

    allow_containers_to_phone_home(&mut ruleset, conf, interfaces)?;

    ruleset.apply_overlay(&mut batch)?;
    ruleset.commit(batch)?;

    Ok(())
}

/// Returns a list of (intrerface_name, ip) tuples
pub fn setup_bridge(conf: &Config) -> Result<Vec<(String, Ipv4Addr)>, Error> {
    match create_bridge(&conf.bridge_name) {
        Ok(_) | Err(nix::errno::Errno::EEXIST) => {}
        Err(e) => return Err(Error::UnixError(e)),
    };

    // give it an IP address
    interface_set_ip(&conf.bridge_name, conf.network)?;

    let mut res = Vec::with_capacity(conf.challenges.len());

    for i in 0..conf.challenges.len() {
        let tap_name = format!("{}-tap{}", conf.bridge_name, i);
        create_tap(&tap_name)?;
        match add_interface_to_bridge(interface_id(&tap_name)?, &conf.bridge_name) {
            Ok(_) | Err(Errno::EBUSY) => {}
            Err(e) => return Err(Error::UnixError(e)),
        }
        set_alias_to_interface(&tap_name, &conf.challenges[i].container_name)
            .map_err(Error::NetworkError)?;
        interface_set_up(&tap_name, true)?;
        res.push((tap_name, conf.challenges[i].container_ip));
    }

    // set the interface as UP
    interface_set_up(&conf.bridge_name, true)?;

    Ok(res)
}
