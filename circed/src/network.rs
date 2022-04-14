use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::iter::once;
use std::net::Ipv4Addr;
use std::rc::Rc;

use ipnetwork::Ipv4Network;
use libc::{getpwnam, ARPHRD_ETHER, IFNAMSIZ};
use nasty_network_ioctls::{
    add_or_delete_route, create_tap, interface_set_ip, interface_set_up, set_alias_to_interface,
};
use nix::errno::Errno;
use once_cell::sync::Lazy;
use rustables::expr::{
    Bitwise, Cmp, CmpOp, Conntrack, Counter, Immediate, Ipv4HeaderField, LLHeaderField, Lookup,
    Masquerade, Meta, Nat, NatType, NetworkHeaderField, Payload, Register, States, TcpHeaderField,
    TransportHeaderField, Verdict,
};
use rustables::query::send_batch;
use rustables::{list_tables, Batch, Chain, MsgType, ProtoFamily, Rule, RuleMethods, Set, Table};
use tracing::error;

use crate::Error;
use circe_common::{Challenge, Config, ConfigError};

static FILTER_TABLE_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_filter").unwrap());
static INPUT_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_input").unwrap());
static OUTPUT_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_output").unwrap());
static FORWARD_CHAIN_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_forward").unwrap());
static NAT_TABLE_NAME: Lazy<CString> = Lazy::new(|| CString::new("circe_nat").unwrap());
static PREROUTING_CHAIN_NAME: Lazy<CString> =
    Lazy::new(|| CString::new("circe_prerouting").unwrap());
static POSTROUTING_CHAIN_NAME: Lazy<CString> =
    Lazy::new(|| CString::new("circe_postrouting").unwrap());

fn create_redirect_from_interface(
    batch: &mut Batch,
    prerouting: Rc<Chain>,
    source_interface: Option<&str>,
    //mut source_interface: impl Iterator<Item = T>,
    saddr: Option<Ipv4Addr>,
    daddr: Option<Ipv4Addr>,
    dport: u16,
    new_target_addr: Ipv4Addr,
    new_target_port: u16,
) {
    /* TODO: properly handle sets
     *
    let set_id = ((sport as u32) << 16) + dport as u32;
    let mut set = Set::<[u8; IFNAMSIZ]>::new(
        CString::new(format!("__set{}", set_id)).unwrap().as_c_str(),
        set_id,
        prerouting.get_table(),
    );

    let mut empty_set = true;
    while let Some(source_interface) = source_interface.next() {
        let mut name_arr = [0u8; libc::IFNAMSIZ];
        for (pos, i) in source_interface.as_ref().bytes().enumerate() {
            name_arr[pos] = i;
        }

        set.add(&name_arr);
        empty_set = false;
    }
    if !empty_set {
        batch.add(&set, MsgType::Add);
        for elem in set.elems_iter() {
            batch.add(&elem, MsgType::Add);
        }
        rule.add_expr(&Meta::IifName);
        rule.add_expr(&Lookup::new(&set).expect("This set has no name"));
    }
    */

    let mut rule = Rule::new(prerouting.clone());
    rule.add_expr(&Meta::L4Proto);
    // L4Proto returns a single byte
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));

    if let Some(source_interface) = source_interface {
        let mut name_arr = [0u8; libc::IFNAMSIZ];
        for (pos, i) in source_interface.bytes().enumerate() {
            name_arr[pos] = i;
        }
        rule.add_expr(&Meta::IifName);
        rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
    }

    if let Some(saddr) = saddr {
        rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
            Ipv4HeaderField::Saddr,
        )));
        rule.add_expr(&Cmp::new(CmpOp::Eq, saddr));
    }
    if let Some(daddr) = daddr {
        rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
            Ipv4HeaderField::Daddr,
        )));
        rule.add_expr(&Cmp::new(CmpOp::Eq, daddr));
    }
    rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
        TcpHeaderField::Dport,
    )));
    rule.add_expr(&Cmp::new(CmpOp::Eq, dport.to_be()));
    rule.add_expr(&Counter {
        nb_bytes: 0,
        nb_packets: 0,
    });
    rule.add_expr(&Immediate::new(new_target_addr.octets(), Register::Reg1));
    rule.add_expr(&Immediate::new(new_target_port.to_be(), Register::Reg2));
    rule.add_expr(&Nat {
        nat_type: NatType::DNat,
        family: ProtoFamily::Ipv4,
        ip_register: Register::Reg1,
        port_register: Some(Register::Reg2),
    });
    batch.add(&rule, MsgType::Add);
}

fn create_port_forwarding(
    batch: &mut Batch,
    prerouting: Rc<Chain>,
    postrouting: Rc<Chain>,
    forward: Rc<Chain>,
    chall: &Challenge,
) {
    let mut name_arr = [0u8; libc::IFNAMSIZ];
    for (pos, i) in chall.tap_name.bytes().enumerate() {
        name_arr[pos] = i;
    }

    // allow packets we just prerouted to go through
    let mut rule = Rule::new(forward.clone());
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
    rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
        Ipv4HeaderField::Daddr,
    )));
    rule.add_expr(&Cmp::new(CmpOp::Eq, chall.container_ip));
    rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
        TcpHeaderField::Dport,
    )));
    rule.add_expr(&Cmp::new(CmpOp::Eq, chall.destination_port.to_be()));
    rule.add_expr(&Meta::OifName);
    rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
    batch.add(&rule.accept(), MsgType::Add);

    // if the app is allowed to go through the internet, masquerade it
    if chall.web_access {
        let mut rule = Rule::new(postrouting);
        rule.add_expr(&Meta::IifName);
        rule.add_expr(&Cmp::new(CmpOp::Eq, name_arr.as_ref()));
        rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(
            Ipv4HeaderField::Saddr,
        )));
        rule.add_expr(&Cmp::new(CmpOp::Eq, chall.container_ip));
        rule.add_expr(&Masquerade);
        batch.add(&rule, MsgType::Add);
    }
}

fn forward_established_packets(batch: &mut Batch, forward: Rc<Chain>) {
    // allow established/related forward packets
    let mut rule = Rule::new(forward);
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
    rule.add_expr(&Conntrack::State);
    let allowed_states = (States::ESTABLISHED | States::RELATED).bits();
    rule.add_expr(&Bitwise::new(allowed_states, 0u32));
    rule.add_expr(&Cmp::new(CmpOp::Neq, 0u32));
    batch.add(&rule.accept(), MsgType::Add);
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
    forward_chain.set_policy(rustables::Policy::Drop);
    batch.add(&forward_chain, MsgType::Add);
    let forward_chain = Rc::new(forward_chain);
    let mut input_chain = Chain::new(&INPUT_CHAIN_NAME.as_ref(), filter_table.clone());
    input_chain.set_type(rustables::ChainType::Filter);
    input_chain.set_hook(rustables::Hook::In, -5i32);
    batch.add(&input_chain, MsgType::Add);
    //let input_chain = Rc::new(input_chain);
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
    let postrouting_chain = Rc::new(postrouting_chain);

    forward_established_packets(&mut batch, forward_chain.clone());

    for chall in conf.challenges.values() {
        println!("Setting up NAT entries for the challenge {}", &chall.name);

        if !conf.network.contains(chall.container_ip) {
            error!(
                "The configuration of challenge '{:?}' contains an invalid IP (out of the target network)",
                chall
            );
            continue;
        }
        create_port_forwarding(
            &mut batch,
            prerouting_chain.clone(),
            postrouting_chain.clone(),
            forward_chain.clone(),
            chall,
        );
        // redirect packets received on port 'chall.source_port' to the challenge
        create_redirect_from_interface(
            &mut batch,
            prerouting_chain.clone(),
            None,
            None,
            None,
            chall.source_port,
            chall.container_ip,
            chall.destination_port,
        );
        /*
        // allow requests from the VM instances to the circed server
        create_redirect_from_interface(
            &mut batch,
            prerouting_chain.clone(),
            Some(&chall.tap_name),
            Some(chall.container_ip),
            Some(conf.network.nth(1).expect("Network too small")),
            conf.listening_port,
            Ipv4Addr::new(127, 0, 0, 1),
            conf.listening_port,
        );
        */
    }

    if let Some(mut batch) = batch.finalize() {
        send_batch(&mut batch)?;
    } else {
        println!("Could not validate the nftables batch");
    }

    Ok(())
}

pub fn setup_interfaces(conf: &Config) -> Result<(), Error> {
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

        println!("Setting up interface {}", &chall.tap_name);

        // EBUSY is expected if the TAP device is already used
        match create_tap(&chall.tap_name, owner_uid) {
            Ok(_) | Err(Errno::EBUSY) => {}
            Err(e) => return Err(Error::UnixError(e)),
        }

        interface_set_ip(
            &chall.tap_name,
            Ipv4Network::new(
                conf.network
                    .nth(1)
                    .expect("The network must be able to host at least one IP address"),
                32,
            )
            .map_err(|_| Error::ConfigurationError(ConfigError::SmallNetwork))?,
        )?;

        let _ = add_or_delete_route(None, chall.container_ip, 32, false);
        let _ = add_or_delete_route(Some(&chall.tap_name), chall.container_ip, 32, true);

        set_alias_to_interface(&chall.tap_name, &chall.name).map_err(Error::NetworkError)?;
        interface_set_up(&chall.tap_name, true)?;
    }

    Ok(())
}

pub fn enable_forwarding() -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/sys/net/ipv4/conf/all/forwarding")?;

    file.write_all(b"1")?;

    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/sys/net/ipv4/conf/default/forwarding")?;

    file.write_all(b"1")?;

    Ok(())
}
