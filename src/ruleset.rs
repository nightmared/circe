use nftnl::query::send_batch;
use nftnl::{
    list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain, ProtoFamily, Rule,
    Table,
};
use std::ffi::{CStr, CString};
use std::{fmt::Debug, sync::Arc};

use tracing::debug;

use crate::Error;

#[derive(Debug)]
pub struct VirtualRuleset {
    userdata: CString,
    tables: Vec<VirtualTable>,
}

impl VirtualRuleset {
    /// `userdata` is used to determine which objects are part of the overlay.
    pub fn new(userdata: CString) -> Result<Self, Error> {
        let nf_tables: Vec<Arc<Table>> = list_tables()?.into_iter().map(Arc::new).collect();

        let mut tables = Vec::with_capacity(nf_tables.len());
        for nf_table in nf_tables {
            tables.push(VirtualTable::new(nf_table, &userdata)?);
        }

        Ok(VirtualRuleset { userdata, tables })
    }

    pub fn add_table(&mut self, table: Arc<Table>) -> Result<(), Error> {
        for cur_table in &self.tables {
            if cur_table.table == table {
                return Err(Error::AlreadyExistsError);
            }
        }
        self.tables.push(VirtualTable {
            table,
            chains: Vec::new(),
            exists: false,
            is_overlay: true,
        });
        Ok(())
    }

    pub fn get_table(&mut self, name: &CStr, family: ProtoFamily) -> Option<&mut VirtualTable> {
        let compare_table = Table::new(&name, family);
        for table in &mut self.tables {
            if *table.table == compare_table {
                return Some(table);
            }
        }
        None
    }

    pub fn write(&mut self) -> Result<(), Error> {
        let mut batch = Batch::new();

        for table in &mut self.tables {
            table.write(&mut batch, &self.userdata)?;
        }

        if let Some(mut batch) = batch.finalize() {
            send_batch(&mut batch)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtualTable {
    pub table: Arc<Table>,
    chains: Vec<VirtualChain>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualTable {
    pub fn new(nf_table: Arc<Table>, userdata: &CStr) -> Result<Self, Error> {
        let nf_chains = list_chains_for_table(nf_table.clone())?;

        let mut chains = Vec::with_capacity(nf_chains.len());
        for chain in nf_chains {
            chains.push(VirtualChain::new(Arc::new(chain), userdata)?);
        }

        let is_overlay = nf_table.get_userdata() == Some(userdata);

        Ok(VirtualTable {
            table: nf_table,
            chains,
            exists: true,
            is_overlay,
        })
    }

    pub fn add_chain(&mut self, chain: Arc<Chain>) -> Result<(), Error> {
        for cur_chain in &self.chains {
            if cur_chain.chain == chain {
                return Err(Error::AlreadyExistsError);
            }
        }

        self.chains.push(VirtualChain {
            chain,
            rules: Vec::new(),
            exists: false,
            is_overlay: true,
        });
        Ok(())
    }

    pub fn get_chain(&mut self, name: &CStr) -> Option<&mut VirtualChain> {
        let compare_chain = Chain::new(&name, self.table.clone());
        for chain in &mut self.chains {
            if *chain.chain == compare_chain {
                return Some(chain);
            }
        }
        None
    }

    fn write(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        for chain in &mut self.chains {
            chain.write(batch, userdata)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtualChain {
    pub chain: Arc<Chain>,
    rules: Vec<VirtualRule>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualChain {
    pub fn new(nf_chain: Arc<Chain>, userdata: &CStr) -> Result<Self, Error> {
        let rules = list_rules_for_chain(&nf_chain)?
            .into_iter()
            .map(|nf_rule| {
                let is_overlay = nf_rule.get_userdata() == Some(userdata);
                VirtualRule {
                    rule: Arc::new(nf_rule),
                    exists: true,
                    is_overlay,
                }
            })
            .collect();
        let is_overlay = nf_chain.get_userdata() == Some(userdata);

        Ok(VirtualChain {
            chain: nf_chain.clone(),
            rules,
            exists: true,
            is_overlay,
        })
    }

    pub fn add_rule(&mut self, rule: Arc<Rule>) -> Result<(), Error> {
        for cur_rule in &self.rules {
            if cur_rule.rule == rule {
                return Err(Error::AlreadyExistsError);
            }
        }
        self.rules.push(VirtualRule {
            rule,
            exists: false,
            is_overlay: true,
        });
        Ok(())
    }

    pub fn get_rule(&mut self, handle: u64) -> Option<&mut VirtualRule> {
        let mut compare_rule = Rule::new(self.chain.clone());
        compare_rule.set_handle(handle);
        for rule in &mut self.rules {
            if *rule.rule == compare_rule {
                return Some(rule);
            }
        }
        None
    }

    fn write(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        for rule in &mut self.rules {
            rule.write(batch, userdata)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtualRule {
    pub rule: Arc<Rule>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualRule {
    fn write(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        if !self.is_overlay || self.exists {
            return Ok(());
        }

        debug!("Creating a new rule {:?}", self.rule.get_str());
        self.rule.set_userdata(userdata);

        batch.add(&self.rule, nftnl::MsgType::Add);

        Ok(())
    }
}
