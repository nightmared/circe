// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use nftnl::{list_chains_for_table, list_rules_for_chain, list_tables, Chain, Rule, Table};
use std::{ffi::CString, fmt::Debug, sync::Arc};
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] nftnl::query::Error),

    #[error("The target obejct already exists")]
    AlreadyExistsError,
}

lazy_static::lazy_static! {
    static ref IN_CHAIN_NAME: CString = CString::new("input").unwrap();
    static ref OUT_CHAIN_NAME: CString = CString::new("output").unwrap();
    static ref FORWARD_CHAIN_NAME: CString = CString::new("forward").unwrap();
    static ref PREROUTING_CHAIN_NAME: CString = CString::new("prerouting").unwrap();
    static ref NAT_CHAIN_NAME: CString = CString::new("nat").unwrap();
}

#[derive(Debug)]
struct VirtualRuleset {
    tables: Vec<VirtualTable>,
}

impl VirtualRuleset {
    fn new() -> Result<Self, Error> {
        let nf_tables: Vec<Arc<Table>> = list_tables()?.into_iter().map(Arc::new).collect();

        let mut tables = Vec::with_capacity(nf_tables.len());
        for nf_table in nf_tables {
            tables.push(VirtualTable::new(nf_table)?);
        }

        Ok(VirtualRuleset { tables })
    }

    fn add_table(&mut self, table: Arc<Table>) -> Result<(), Error> {
        for cur_table in &self.tables {
            if cur_table.table == table {
                return Err(Error::AlreadyExistsError);
            }
        }
        self.tables.push(VirtualTable {
            table,
            chains: Vec::new(),
            is_overlay: true,
        });
        Ok(())
    }
}

#[derive(Debug)]
struct VirtualTable {
    pub table: Arc<Table>,
    pub chains: Vec<VirtualChain>,
    is_overlay: bool,
}

impl VirtualTable {
    fn new(nf_table: Arc<Table>) -> Result<Self, Error> {
        let nf_chains = list_chains_for_table(nf_table.clone())?;

        let mut chains = Vec::with_capacity(nf_chains.len());
        for chain in nf_chains {
            chains.push(VirtualChain::new(Arc::new(chain))?);
        }

        Ok(VirtualTable {
            table: nf_table,
            chains,
            is_overlay: false,
        })
    }

    fn add_chain(&mut self, chain: Arc<Chain>) -> Result<(), Error> {
        for cur_chain in &self.chains {
            if cur_chain.chain == chain {
                return Err(Error::AlreadyExistsError);
            }
        }
        self.chains.push(VirtualChain {
            chain,
            rules: Vec::new(),
            is_overlay: true,
        });
        Ok(())
    }
}

#[derive(Debug)]
struct VirtualChain {
    pub chain: Arc<Chain>,
    pub rules: Vec<VirtualRule>,
    is_overlay: bool,
}

impl VirtualChain {
    fn new(nf_chain: Arc<Chain>) -> Result<Self, Error> {
        Ok(VirtualChain {
            chain: nf_chain.clone(),
            rules: list_rules_for_chain(&nf_chain)?
                .into_iter()
                .map(|rule| VirtualRule {
                    rule: Arc::new(rule),
                    is_overlay: false,
                })
                .collect(),
            is_overlay: false,
        })
    }

    fn add_rule(&mut self, rule: Arc<Rule>) -> Result<(), Error> {
        for cur_rule in &self.rules {
            if cur_rule.rule == rule {
                return Err(Error::AlreadyExistsError);
            }
        }
        self.rules.push(VirtualRule {
            rule,
            is_overlay: true,
        });
        Ok(())
    }
}

#[derive(Debug)]
struct VirtualRule {
    pub rule: Arc<Rule>,
    is_overlay: bool,
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    //let tables = list_tables()?;
    //for table in tables {
    //    let chains = list_chains_for_table(&table)?;
    //    for chain in chains.iter() {
    //        println!("chains: {:?}", chain);
    //        let rules = list_rules_for_chain(&chain)?;
    //        for rule in rules {
    //            println!("{:?}", rule.get_str());
    //        }
    //    }
    //}
    let ruleset = VirtualRuleset::new()?;
    println!("{:?}", ruleset);
    Ok(())
}
