// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::sync::Arc;

use nftnl::expr::{Expression, Log};
use nftnl::Rule;
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

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let mut ruleset = VirtualRuleset::new(CString::new("GeneratedByCIRCE").unwrap())?;
    let table = ruleset
        .get_table(&FILTER_TABLE_NAME, nftnl::ProtoFamily::Inet)
        .unwrap();
    let chain = table.get_chain(&IN_CHAIN_NAME).unwrap();

    let mut rule = Rule::new(chain.chain.clone());
    rule.add_expr(&Log);
    chain.add_rule(Arc::new(rule))?;

    ruleset.write()?;

    //println!("{:?}", ruleset);
    Ok(())
}
