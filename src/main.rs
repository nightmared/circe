// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;

use rustables::expr::{
    Cmp, CmpOp, Counter, Immediate, Meta, Nat, NatType, Payload, Register, TcpHeaderField, ToSlice,
    TransportHeaderField,
};
use rustables::{expr::ExpressionWrapper, Chain, ProtoFamily, Rule, Table};
use tracing::error;

mod config;
use config::Config;

mod ruleset;
use ruleset::VirtualRuleset;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] rustables::query::Error),

    #[error("The target obejct already exists")]
    AlreadyExistsError,

    #[error("The configuration file presents an issue")]
    ConfigurationFileError(#[source] std::io::Error),

    #[error("The configuration couldn't be parsed")]
    ConfigurationParsingError(#[from] toml::de::Error),
}

lazy_static::lazy_static! {
    static ref FILTER_TABLE_NAME: CString = CString::new("filter").unwrap();
    static ref NAT_TABLE_NAME: CString = CString::new("nat").unwrap();
    static ref IN_CHAIN_NAME: CString = CString::new("input").unwrap();
    static ref OUT_CHAIN_NAME: CString = CString::new("output").unwrap();
    static ref FORWARD_CHAIN_NAME: CString = CString::new("forward").unwrap();
    static ref PREROUTING_CHAIN_NAME: CString = CString::new("prerouting").unwrap();
    static ref NAT_CHAIN_NAME: CString = CString::new("nat").unwrap();
}

fn get_or_create_rule(
    ruleset: &mut VirtualRuleset,
    family: ProtoFamily,
    table_name: impl AsRef<CStr>,
    chain_name: impl AsRef<CStr>,
    cb: impl Fn(&mut Rule) -> Result<(), Error>,
) -> Result<(), Error> {
    let table = match ruleset.get_table(table_name.as_ref(), family) {
        Some(v) => v,
        None => ruleset.add_table(Rc::new(Table::new(&table_name.as_ref(), family)))?,
    };
    let chain = match table.get_chain(chain_name.as_ref()) {
        Some(v) => v,
        None => table.add_chain(Rc::new(Chain::new(
            &chain_name.as_ref(),
            table.table.clone(),
        )))?,
    };

    let mut rule = Rule::new(chain.chain.clone());

    cb(&mut rule)?;

    chain.add_rule(Rc::new(rule))?;

    Ok(())
}

fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    // load the configuration
    let mut config_file =
        File::open("config.toml").map_err(|x| Error::ConfigurationFileError(x))?;
    let mut config_content = String::with_capacity(5000);
    config_file
        .read_to_string(&mut config_content)
        .map_err(|x| Error::ConfigurationFileError(x))?;
    let config: Config = toml::from_str(&config_content)?;

    // setup the nftables mappings
    let mut ruleset = VirtualRuleset::new(CString::new("GeneratedByCIRCE").unwrap())?;
    //println!("{:?}", ruleset);
    let rules = &ruleset
        .get_table(NAT_TABLE_NAME.as_ref(), ProtoFamily::Ipv4)
        .unwrap()
        .get_chain(PREROUTING_CHAIN_NAME.as_ref())
        .unwrap()
        .rules;
    let rule = &rules[rules.len() - 1].rule;
    println!(
        "{:?}",
        rule.get_exprs()
            .map(|x| x.get_expr_kind().unwrap().to_owned())
            .collect::<Vec<CString>>()
    );

    ruleset.delete_overlay()?;

    for site in config.sites {
        if !config.network.contains(site.container_ip) {
            error!(
                "Site '{:?}' contains an invalid IP (out of the target network)",
                site
            );
            continue;
        }
        println!("{:?}", libc::IPPROTO_TCP.to_slice().len());
        get_or_create_rule(
            &mut ruleset,
            ProtoFamily::Ipv4,
            NAT_TABLE_NAME.as_ref(),
            PREROUTING_CHAIN_NAME.as_ref(),
            |rule| {
                rule.add_expr(&Meta::L4Proto);
                // L4Proto returns a single byte
                rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
                rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
                    TcpHeaderField::Dport,
                )));
                rule.add_expr(&Cmp::new(CmpOp::Eq, site.source_port));
                rule.add_expr(&Immediate::new(site.container_ip.octets(), Register::Reg1));
                rule.add_expr(&Immediate::new(
                    site.destination_port.to_be(),
                    Register::Reg2,
                ));
                rule.add_expr(&Counter {
                    nb_bytes: 1337666,
                    nb_packets: 42,
                });
                rule.add_expr(&Nat {
                    nat_type: NatType::DNat,
                    family: ProtoFamily::Ipv4,
                    ip_register: Register::Reg1,
                    port_register: Some(Register::Reg2),
                });
                //rule.add_expr(Comment
                Ok(())
            },
        )?;
    }

    ruleset.apply_overlay()?;

    Ok(())
}
