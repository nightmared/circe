use nftnl::query::send_batch;
use nftnl::{
    list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain, ProtoFamily, Rule,
    Table,
};
use std::ffi::{CStr, CString};
use std::ops::RangeBounds;
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
        let mut res = VirtualRuleset {
            userdata,
            tables: Vec::new(),
        };

        res.sync()?;

        Ok(res)
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

    pub fn sync(&mut self) -> Result<(), Error> {
        let nf_tables: Vec<Arc<Table>> = list_tables()?.into_iter().map(Arc::new).collect();
        let nf_objects: Vec<Arc<Table>> = self.tables.iter().map(|x| x.table.clone()).collect();

        // Add missing tables
        for nf_table in &nf_tables {
            if !nf_objects.contains(&nf_table) {
                self.tables
                    .push(VirtualTable::new(nf_table.clone(), &self.userdata)?);
            }
        }

        // Delete tables that remain but are no longer in use
        let nf_objets_to_delete: Vec<Arc<Table>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_tables.contains(&obj))
            .collect();

        for idx in (0..self.tables.len()).rev() {
            if nf_objets_to_delete.contains(&self.tables[idx].table) {
                self.tables.swap_remove(idx);
            }
        }

        for table in &mut self.tables {
            table.sync(&self.userdata)?;
        }

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

    pub fn apply_overlay(&mut self) -> Result<(), Error> {
        let mut batch = Batch::new();

        for table in &mut self.tables {
            table.apply_overlay(&mut batch, &self.userdata)?;
        }

        if let Some(mut batch) = batch.finalize() {
            send_batch(&mut batch)?;
        }

        self.sync()?;

        Ok(())
    }

    pub fn delete_overlay(&mut self) -> Result<(), Error> {
        let mut batch = Batch::new();

        for table in &mut self.tables {
            table.delete_overlay(&mut batch)?;
        }

        if let Some(mut batch) = batch.finalize() {
            send_batch(&mut batch)?;
        }

        self.sync()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VirtualTable {
    pub table: Arc<Table>,
    chains: Vec<VirtualChain>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualTable {
    pub fn new(nf_table: Arc<Table>, userdata: &CStr) -> Result<Self, Error> {
        let is_overlay = nf_table.get_userdata() == Some(userdata);

        let mut res = VirtualTable {
            table: nf_table,
            chains: Vec::new(),
            exists: true,
            is_overlay,
        };

        res.sync(userdata)?;

        Ok(res)
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

    fn sync(&mut self, userdata: &CStr) -> Result<(), Error> {
        let nf_chains: Vec<Arc<Chain>> = list_chains_for_table(self.table.clone())?
            .into_iter()
            .map(Arc::new)
            .collect();
        let nf_objects: Vec<Arc<Chain>> = self.chains.iter().map(|x| x.chain.clone()).collect();

        // Add missing chains
        for nf_chain in &nf_chains {
            if !nf_objects.contains(&nf_chain) {
                self.chains
                    .push(VirtualChain::new(nf_chain.clone(), userdata)?);
            }
        }

        // Delete chains that remain but are no longer in use
        let nf_objets_to_delete: Vec<Arc<Chain>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_chains.contains(&obj))
            .collect();

        for idx in (0..self.chains.len()).rev() {
            if nf_objets_to_delete.contains(&self.chains[idx].chain) {
                self.chains.swap_remove(idx);
            }
        }

        for chain in &mut self.chains {
            chain.sync(userdata)?;
        }

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

    fn apply_overlay(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        for chain in &mut self.chains {
            chain.apply_overlay(batch, userdata)?;
        }

        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.table, nftnl::MsgType::Del);
        } else {
            for chain in &mut self.chains {
                chain.delete_overlay(batch)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VirtualChain {
    pub chain: Arc<Chain>,
    rules: Vec<VirtualRule>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualChain {
    pub fn new(nf_chain: Arc<Chain>, userdata: &CStr) -> Result<Self, Error> {
        let is_overlay = nf_chain.get_userdata() == Some(userdata);

        let mut res = VirtualChain {
            chain: nf_chain.clone(),
            rules: Vec::new(),
            exists: true,
            is_overlay,
        };

        res.sync(userdata)?;

        Ok(res)
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

    fn sync(&mut self, userdata: &CStr) -> Result<(), Error> {
        let nf_rules: Vec<Arc<Rule>> = list_rules_for_chain(&self.chain)?
            .into_iter()
            .map(Arc::new)
            .collect();
        let nf_objects: Vec<Arc<Rule>> = self.rules.iter().map(|x| x.rule.clone()).collect();

        // Add missing rules
        for nf_rule in &nf_rules {
            if !nf_objects.contains(&nf_rule) {
                self.rules.push(VirtualRule {
                    rule: nf_rule.clone(),
                    exists: true,
                    is_overlay: nf_rule.get_userdata() == Some(userdata),
                });
            }
        }

        // Delete rules that remain but are no longer in use
        let nf_objets_to_delete: Vec<Arc<Rule>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_rules.contains(&obj))
            .collect();

        for idx in (0..self.rules.len()).rev() {
            if nf_objets_to_delete.contains(&self.rules[idx].rule) {
                self.rules.swap_remove(idx);
            }
        }

        Ok(())
    }

    fn apply_overlay(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        for rule in &mut self.rules {
            rule.apply_overlay(batch, userdata)?;
        }
        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.chain, nftnl::MsgType::Del);
        } else {
            for rule in &mut self.rules {
                rule.delete_overlay(batch)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VirtualRule {
    pub rule: Arc<Rule>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualRule {
    fn apply_overlay(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        if !self.is_overlay || self.exists {
            return Ok(());
        }

        debug!("Creating a new rule {:?}", self.rule.get_str());
        self.rule.set_userdata(userdata);

        batch.add(&self.rule, nftnl::MsgType::Add);

        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.rule, nftnl::MsgType::Del);
        }

        Ok(())
    }
}
