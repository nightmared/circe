// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;

use rustables::expr::{
    Cmp, CmpOp, Counter, Immediate, Meta, Nat, NatType, Payload, Register, TcpHeaderField,
    TransportHeaderField,
};
use rustables::{Batch, Chain, ProtoFamily, Rule, Table};
use tracing::{debug, error};

mod bridge;
use bridge::{create_bridge, delete_bridge, BridgeBuilder};

mod config;
use config::{Config, Site};

mod ruleset;
use ruleset::VirtualRuleset;

use crate::bridge::{interface_get_flags, interface_set_flags, interface_set_ip};

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

    #[error("Error while manipulating UNIX objects")]
    UnixError(#[from] nix::Error),
}

lazy_static::lazy_static! {
    static ref FILTER_TABLE_NAME: CString = CString::new("filter").unwrap();
    static ref NAT_TABLE_NAME: CString = CString::new("nat").unwrap();
    static ref INPUT_CHAIN_NAME: CString = CString::new("input").unwrap();
    static ref OUTPUT_CHAIN_NAME: CString = CString::new("output").unwrap();
    static ref FORWARD_CHAIN_NAME: CString = CString::new("forward").unwrap();
    static ref PREROUTING_CHAIN_NAME: CString = CString::new("prerouting").unwrap();
    static ref NAT_CHAIN_NAME: CString = CString::new("nat").unwrap();
}

fn get_or_create_rule(
    ruleset: &mut VirtualRuleset,
    family: ProtoFamily,
    table_name: impl AsRef<CStr>,
    cb_table: impl Fn(&mut Table) -> Result<(), Error>,
    chain_name: impl AsRef<CStr>,
    cb_chain: impl Fn(&mut Chain) -> Result<(), Error>,
    cb_rule: impl Fn(&mut Rule) -> Result<(), Error>,
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

    let mut rule = Rule::new(chain.chain.clone());

    cb_rule(&mut rule)?;

    if let Err(e) = chain.add_rule(Rc::new(rule)) {
        match e {
            Error::AlreadyExistsError => {}
            _ => return Err(e),
        }
    }

    Ok(())
}

fn create_port_forwarding(ruleset: &mut VirtualRuleset, site: &Site) -> Result<(), Error> {
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
        |rule| {
            rule.add_expr(&Meta::L4Proto);
            // L4Proto returns a single byte
            rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));
            rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
                TcpHeaderField::Dport,
            )));
            rule.add_expr(&Cmp::new(CmpOp::Eq, site.source_port.to_be()));
            rule.add_expr(&Immediate::new(site.container_ip.octets(), Register::Reg1));
            rule.add_expr(&Immediate::new(site.destination_port, Register::Reg2));
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
            Ok(())
        },
    )
}

fn setup_nat(conf: &Config) -> Result<(), Error> {
    let mut ruleset = VirtualRuleset::new(CString::new("GeneratedByCIRCE").unwrap())?;

    // TODO: perform that operation atomically
    let mut batch = Batch::new();
    ruleset.delete_overlay(&mut batch)?;
    ruleset.commit(batch)?;

    for site in &conf.sites {
        if !conf.network.contains(site.container_ip) {
            error!(
                "Site '{:?}' contains an invalid IP (out of the target network)",
                site
            );
            continue;
        }
        create_port_forwarding(&mut ruleset, site)?;
    }

    let mut batch = Batch::new();
    ruleset.apply_overlay(&mut batch)?;
    ruleset.commit(batch)?;

    Ok(())
}

fn setup_bridge(conf: &Config) -> Result<(), Error> {
    const IFF_UP: u32 = 0x1;

    match bridge::interface_get_flags(&conf.bridge_name) {
        Ok(cur_flags) => {
            // if the interace is present and up, set it down, otherwise we will not be able to
            // delete it
            if cur_flags & IFF_UP != 0 {
                debug!("The interface was up, setting it down");
                bridge::interface_set_flags(&conf.bridge_name, cur_flags & (!IFF_UP))?;
            }
            delete_bridge(&conf.bridge_name)?;
        }
        Err(nix::Error::ENXIO) => {}
        Err(e) => return Err(e)?,
    }

    create_bridge(&conf.bridge_name)?;

    // set the interface as UP
    interface_set_flags(
        &conf.bridge_name,
        interface_get_flags(&conf.bridge_name)? | IFF_UP,
    )?;

    // give it an IP address
    interface_set_ip(&conf.bridge_name, conf.network)?;

    Ok(())
}

fn setup_network(conf: Config) -> Result<(), Error> {
    setup_bridge(&conf)?;

    setup_nat(&conf)
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

    setup_network(config.clone())?;

    Ok(())
}
