// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;

use libc::EEXIST;
use rustables::expr::{
    Cmp, CmpOp, Counter, Immediate, Meta, Nat, NatType, Payload, Register, TcpHeaderField,
    TransportHeaderField,
};
use rustables::{Batch, Chain, ProtoFamily, Rule, Table};
use tracing::{debug, error};

use nasty_network_ioctls::{
    add_interface_to_bridge, create_bridge, create_tap, interface_get_flags, interface_id,
    interface_is_up, interface_set_flags, interface_set_ip, interface_set_up, BridgeBuilder,
};

mod config;
use config::{Config, Site};

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
    ruleset.reload_state_from_system()?;

    // atomic nftables configuration
    let mut batch = Batch::new();
    ruleset.delete_overlay(&mut batch)?;

    let mut ruleset = VirtualRuleset::new(CString::new("GeneratedByCIRCE").unwrap())?;
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

    ruleset.apply_overlay(&mut batch)?;
    ruleset.commit(batch)?;

    Ok(())
}

fn delete_bridge(interface_name: &str) -> Result<(), Error> {
    // if the interace is present and up, set it down, otherwise we will not be able to
    // delete it
    match interface_is_up(interface_name) {
        Ok(up) => {
            if up {
                debug!("The interface was up, setting it down");
                interface_set_up(interface_name, false)?;
            }
            nasty_network_ioctls::delete_bridge(&interface_name)?;
            Ok(())
        }
        Err(nix::Error::ENODEV) => Ok(()),
        Err(e) => Err(Error::UnixError(e)),
    }
}

fn setup_bridge(conf: &Config) -> Result<(), Error> {
    // TODO: no longer needed in production
    // delete_bridge(&conf.bridge_name)?;

    match create_bridge(&conf.bridge_name) {
        Ok(_) | Err(nix::errno::Errno::EEXIST) => {}
        Err(e) => return Err(Error::UnixError(e)),
    };

    // give it an IP address
    interface_set_ip(&conf.bridge_name, conf.network)?;

    let mut i = 0;
    for site in &conf.sites {
        let tap_name = format!("{}-{}", conf.bridge_name, i);
        create_tap(&tap_name)?;
        add_interface_to_bridge(interface_id(&tap_name)?, &conf.bridge_name)?;
        interface_set_up(&tap_name, true)?;
        i += 1;
    }

    // set the interface as UP
    interface_set_up(&conf.bridge_name, true)?;

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
