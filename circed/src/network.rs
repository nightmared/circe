use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use std::rc::Rc;

use ipnetwork::Ipv4Network;
use libc::getpwnam;
use nasty_network_ioctls::{
    add_interface_to_bridge, create_bridge, create_tap, interface_id, interface_set_ip,
    interface_set_up, set_alias_to_interface,
};
use nix::errno::Errno;
use once_cell::sync::Lazy;
use rustables::expr::{
    Bitwise, Cmp, CmpOp, Conntrack, Counter, Immediate, Ipv4HeaderField, Meta, Nat, NatType,
    NetworkHeaderField, Payload, Register, States, TcpHeaderField, TransportHeaderField, Verdict,
};
use rustables::query::send_batch;
use rustables::{list_tables, Batch, Chain, MsgType, ProtoFamily, Rule, RuleMethods, Table};
use tracing::error;

use crate::Error;
use circe_common::{Challenge, Config};

static FILTER_TABLE_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_filter").unwrap());
static INPUT_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_input").unwrap());
static OUTPUT_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_output").unwrap());
static FORWARD_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_forward").unwrap());
static NAT_TABLE_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_nat").unwrap());
static PREROUTING_CHAIN_NAME: Lazy<CString> =
    Lazy::new(|| CString::new("circe_prerouting").unwrap());
static POSTROUTING_CHAIN_NAME: Lazy<CString> =
    Lazy::new(|| CString::new("circe_postrouting").unwrap());

fn allow_containers_to_phone_home(batch: &mut Batch, input: Rc<Chain>, conf: &Config) {
    for chall in conf.challenges.values() {
        let mut name_arr = [0u8; libc::IFNAMSIZ];
        for (pos, i) in chall.tap_name.bytes().enumerate() {
            name_arr[pos] = i;
        }

        // allow requests from the VM instances to the circed server
        let mut rule = Rule::new(input.clone());
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
        rule.add_expr(&Cmp::new(
            CmpOp::Eq,
            conf.network
                .nth(1)
                .expect("Invalid network: too small to hold the gateway"),
        ));
        rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
            Ipv4HeaderField::Saddr,
        )));
        rule.add_expr(&Cmp::new(CmpOp::Eq, chall.container_ip));
        batch.add(&rule.accept(), MsgType::Add);
    }
}

fn create_port_forwarding(batch: &mut Batch, prerouting: Rc<Chain>, chall: &Challenge) {
    // redirect packets received on chall.sources to the challenge
    let mut rule = Rule::new(prerouting);
    rule.add_expr(&Meta::L4Proto);
    // L4Proto returns a single byte
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
    rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
        TcpHeaderField::Dport,
    )));
    rule.add_expr(&Cmp::new(CmpOp::Eq, chall.source_port.to_be()));
    rule.add_expr(&Counter {
        nb_bytes: 0,
        nb_packets: 0,
    });
    rule.add_expr(&Immediate::new(chall.container_ip.octets(), Register::Reg1));
    rule.add_expr(&Immediate::new(
        chall.destination_port.to_be(),
        Register::Reg2,
    ));
    rule.add_expr(&Nat {
        nat_type: NatType::DNat,
        family: ProtoFamily::Ipv4,
        ip_register: Register::Reg1,
        port_register: Some(Register::Reg2),
    });
    batch.add(&rule, MsgType::Add);
}

fn disable_arbitrary_forwarding(batch: &mut Batch, forward: Rc<Chain>, interface_name: &str) {
    let mut name_arr = [0u8; libc::IFNAMSIZ];
    for (pos, i) in interface_name.bytes().enumerate() {
        name_arr[pos] = i;
    }

    // allow established/related output packets
    let mut rule = Rule::new(forward.clone());
    rule.add_expr(&Meta::IifName);
    rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
    rule.add_expr(&Conntrack::State);
    let allowed_states = (States::ESTABLISHED | States::RELATED).bits();
    rule.add_expr(&Bitwise::new(allowed_states, 0u32));
    rule.add_expr(&Cmp::new(CmpOp::Neq, 0u32));
    batch.add(&rule.accept(), MsgType::Add);

    let mut rule = Rule::new(forward.clone());
    rule.add_expr(&Meta::IifName);
    rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
    rule.add_expr(&Counter::new());
    rule.add_expr(&Verdict::Drop);
    batch.add(&rule, MsgType::Add);

    let mut rule = Rule::new(forward);
    rule.add_expr(&Counter::new());
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

pub fn setup_nat(conf: &Config) -> Result<(), Error> {
    enable_forwarding()?;

    // atomic nftables configuration
    let mut batch = Batch::new();

    // delete existing tables
    for table in list_tables()? {
        if table.get_name() == NAT_TABLE_NAME.as_ref()
            || table.get_name() == FILTER_TABLE_NAME.as_ref()
        {
            batch.add(&table, rustables::MsgType::Del);
        }
    }

    let filter_table = Rc::new(Table::new(&FILTER_TABLE_NAME.as_ref(), ProtoFamily::Ipv4));
    batch.add(&filter_table, MsgType::Add);
    let mut forward_chain = Chain::new(&FORWARD_CHAIN_NAME.as_ref(), filter_table.clone());
    forward_chain.set_type(rustables::ChainType::Filter);
    forward_chain.set_hook(rustables::Hook::Forward, -5i32);
    // disable forwarding by default
    forward_chain.set_policy(rustables::Policy::Drop);
    batch.add(&forward_chain, MsgType::Add);
    let forward_chain = Rc::new(forward_chain);
    let mut input_chain = Chain::new(&INPUT_CHAIN_NAME.as_ref(), filter_table.clone());
    input_chain.set_type(rustables::ChainType::Filter);
    input_chain.set_hook(rustables::Hook::In, -5i32);
    batch.add(&input_chain, MsgType::Add);
    let input_chain = Rc::new(input_chain);
    let mut output_chain = Chain::new(&OUTPUT_CHAIN_NAME.as_ref(), filter_table);
    output_chain.set_type(rustables::ChainType::Filter);
    output_chain.set_hook(rustables::Hook::Out, -5i32);
    batch.add(&output_chain, MsgType::Add);
    let output_chain = Rc::new(output_chain);

    let nat_table = Rc::new(Table::new(&NAT_TABLE_NAME.as_ref(), ProtoFamily::Ipv4));
    batch.add(&nat_table, MsgType::Add);
    let mut prerouting_chain = Chain::new(&PREROUTING_CHAIN_NAME.as_ref(), nat_table.clone());
    prerouting_chain.set_type(rustables::ChainType::Nat);
    prerouting_chain.set_hook(rustables::Hook::PreRouting, -100i32);
    batch.add(&prerouting_chain, MsgType::Add);
    let mut postrouting_chain = Chain::new(&POSTROUTING_CHAIN_NAME.as_ref(), nat_table);
    postrouting_chain.set_type(rustables::ChainType::Nat);
    postrouting_chain.set_hook(rustables::Hook::PostRouting, 100i32);
    batch.add(&postrouting_chain, MsgType::Add);
    let prerouting_chain = Rc::new(prerouting_chain);

    for chall in conf.challenges.values() {
        if !conf.network.contains(chall.container_ip) {
            error!(
                "The configuration of challenge '{:?}' contains an invalid IP (out of the target network)",
                chall
            );
            continue;
        }
        create_port_forwarding(&mut batch, prerouting_chain.clone(), chall);
    }

    allow_containers_to_phone_home(&mut batch, input_chain, &conf);

    disable_arbitrary_forwarding(&mut batch, forward_chain, &conf.bridge_name);

    if let Some(mut batch) = batch.finalize() {
        send_batch(&mut batch)?;
    }

    Ok(())
}

pub fn setup_bridge(conf: &Config) -> Result<(), Error> {
    match create_bridge(&conf.bridge_name) {
        Ok(_) | Err(nix::errno::Errno::EEXIST) => {}
        Err(e) => return Err(Error::UnixError(e)),
    };

    let interface_ip = Ipv4Network::new(
        conf.network
            .nth(1)
            .expect("Invalid network: too small to hold the gateway"),
        conf.network.prefix(),
    )
    .unwrap();

    interface_set_ip(&conf.bridge_name, interface_ip)?;

    for chall in conf.challenges.values() {
        let owner_uid = unsafe {
            let cstr = CString::new(conf.user.as_bytes()).unwrap();
            let ptr = getpwnam(cstr.as_ptr());
            if ptr.is_null() {
                return Err(Error::UnknownUser);
            } else {
                (*ptr).pw_uid
            }
        };

        // EBUSY is expected if the TAP device is already used
        match create_tap(&chall.tap_name, owner_uid) {
            Ok(_) | Err(Errno::EBUSY) => {}
            Err(e) => return Err(Error::UnixError(e)),
        }

        match add_interface_to_bridge(interface_id(&chall.tap_name)?, &conf.bridge_name) {
            Ok(_) | Err(Errno::EBUSY) => {}
            Err(e) => return Err(Error::UnixError(e)),
        }
        set_alias_to_interface(&chall.tap_name, &chall.name).map_err(Error::NetworkError)?;
        interface_set_up(&chall.tap_name, true)?;
    }

    interface_set_up(&conf.bridge_name, true)?;

    Ok(())
}

pub fn enable_forwarding() -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/sys/net/ipv4/conf/all/forwarding")?;

    file.write_all(b"1")?;

    Ok(())
}
