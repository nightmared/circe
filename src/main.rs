// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::sync::Arc;

use nftnl::expr::{Expression, Log};
use nftnl::{Chain, ProtoFamily, Rule, Table};
use tracing::error;

mod ruleset;
use ruleset::{VirtualChain, VirtualRule, VirtualRuleset, VirtualTable};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] nftnl::query::Error),

    #[error("The target obejct already exists")]
    AlreadyExistsError,
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
        None => ruleset.add_table(Arc::new(Table::new(&table_name.as_ref(), family)))?,
    };
    let chain = match table.get_chain(chain_name.as_ref()) {
        Some(v) => v,
        None => table.add_chain(Arc::new(Chain::new(
            &chain_name.as_ref(),
            table.table.clone(),
        )))?,
    };

    let mut rule = Rule::new(chain.chain.clone());

    cb(&mut rule)?;

    chain.add_rule(Arc::new(rule))?;

    Ok(())
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let mut ruleset = VirtualRuleset::new(CString::new("GeneratedByCIRCE").unwrap())?;

    get_or_create_rule(
        &mut ruleset,
        ProtoFamily::Inet,
        NAT_TABLE_NAME.as_ref(),
        PREROUTING_CHAIN_NAME.as_ref(),
        |rule| {
            rule.add_expr(&Log);
            Ok(())
        },
    )?;

    ruleset.apply_overlay()?;

    std::thread::sleep_ms(5000);

    ruleset.delete_overlay()?;

    //println!("{:?}", ruleset);
    Ok(())
}
