use rustables::query::send_batch;
use rustables::{
    list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain, MsgType, ProtoFamily,
    Rule, Table,
};
use std::ffi::{CStr, CString};
use std::{fmt::Debug, rc::Rc};

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

        Ok(res)
    }

    pub fn add_table(&mut self, table: Rc<Table>) -> Result<&mut VirtualTable, Error> {
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

        let pos = self.tables.len() - 1;
        Ok(&mut self.tables[pos])
    }

    pub fn reload_state_from_system(&mut self) -> Result<(), Error> {
        let nf_tables: Vec<Rc<Table>> = list_tables()?.into_iter().map(Rc::new).collect();
        let nf_objects: Vec<Rc<Table>> = self.tables.iter().map(|x| x.table.clone()).collect();

        // Add missing tables
        for nf_table in &nf_tables {
            if !nf_objects.contains(&nf_table) {
                self.tables
                    .push(VirtualTable::new(nf_table.clone(), &self.userdata)?);
            }
        }

        // Delete tables that remain but are no longer in use
        let nf_objets_to_delete: Vec<Rc<Table>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_tables.contains(&obj))
            .collect();

        for idx in (0..self.tables.len()).rev() {
            if nf_objets_to_delete.contains(&self.tables[idx].table) {
                self.tables.swap_remove(idx);
            } else {
                self.tables[idx].exists = true;
            }
        }

        for table in &mut self.tables {
            table.reload_state_from_system(&self.userdata)?;
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

    pub fn apply_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        for table in &mut self.tables {
            table.apply_overlay(batch, &self.userdata)?;
        }

        Ok(())
    }

    pub fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        for table in &mut self.tables {
            table.delete_overlay(batch)?;
        }

        Ok(())
    }

    pub fn commit(&mut self, batch: Batch) -> Result<(), Error> {
        if let Some(mut batch) = batch.finalize() {
            send_batch(&mut batch)?;
        }

        self.reload_state_from_system()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VirtualTable {
    pub table: Rc<Table>,
    chains: Vec<VirtualChain>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualTable {
    pub fn new(nf_table: Rc<Table>, userdata: &CStr) -> Result<Self, Error> {
        let is_overlay = nf_table.get_userdata() == Some(userdata);

        let mut res = VirtualTable {
            table: nf_table,
            chains: Vec::new(),
            exists: true,
            is_overlay,
        };

        res.reload_state_from_system(userdata)?;

        Ok(res)
    }

    pub fn add_chain(&mut self, chain: Rc<Chain>) -> Result<&mut VirtualChain, Error> {
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

        let pos = self.chains.len() - 1;
        Ok(&mut self.chains[pos])
    }

    fn reload_state_from_system(&mut self, userdata: &CStr) -> Result<(), Error> {
        let nf_chains: Vec<Rc<Chain>> = list_chains_for_table(self.table.clone())?
            .into_iter()
            .map(Rc::new)
            .collect();
        let nf_objects: Vec<Rc<Chain>> = self.chains.iter().map(|x| x.chain.clone()).collect();

        // Add missing chains
        for nf_chain in &nf_chains {
            if !nf_objects.contains(&nf_chain) {
                self.chains
                    .push(VirtualChain::new(nf_chain.clone(), userdata)?);
            }
        }

        // Delete chains that remain but are no longer in use
        let nf_objets_to_delete: Vec<Rc<Chain>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_chains.contains(&obj))
            .collect();

        for idx in (0..self.chains.len()).rev() {
            if nf_objets_to_delete.contains(&self.chains[idx].chain) {
                self.chains.swap_remove(idx);
            } else {
                self.chains[idx].exists = true;
            }
        }

        for chain in &mut self.chains {
            chain.reload_state_from_system(userdata)?;
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
        if self.is_overlay && !self.exists {
            debug!("Creating a new table {:?}", self.table.get_str());
            self.table.set_userdata(userdata);

            batch.add(&self.table, MsgType::Add);
        }

        for chain in &mut self.chains {
            chain.apply_overlay(batch, userdata)?;
        }

        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.table, MsgType::Del);
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
    pub chain: Rc<Chain>,
    pub rules: Vec<VirtualRule>,
    exists: bool,
    is_overlay: bool,
}

impl VirtualChain {
    pub fn new(nf_chain: Rc<Chain>, userdata: &CStr) -> Result<Self, Error> {
        let is_overlay = nf_chain.get_userdata() == Some(userdata);

        let mut res = VirtualChain {
            chain: nf_chain.clone(),
            rules: Vec::new(),
            exists: true,
            is_overlay,
        };

        res.reload_state_from_system(userdata)?;

        Ok(res)
    }

    pub fn add_rule(&mut self, rule: Rc<Rule>) -> Result<&mut VirtualRule, Error> {
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

        let pos = self.rules.len() - 1;
        Ok(&mut self.rules[pos])
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

    fn reload_state_from_system(&mut self, userdata: &CStr) -> Result<(), Error> {
        let nf_rules: Vec<Rc<Rule>> = list_rules_for_chain(&self.chain)?
            .into_iter()
            .map(Rc::new)
            .collect();
        let nf_objects: Vec<Rc<Rule>> = self.rules.iter().map(|x| x.rule.clone()).collect();

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
        let nf_objets_to_delete: Vec<Rc<Rule>> = nf_objects
            .into_iter()
            .filter(|obj| !nf_rules.contains(&obj))
            .collect();

        for idx in (0..self.rules.len()).rev() {
            if nf_objets_to_delete.contains(&self.rules[idx].rule) {
                self.rules.swap_remove(idx);
            } else {
                self.rules[idx].exists = true;
            }
        }

        Ok(())
    }

    fn apply_overlay(&mut self, batch: &mut Batch, userdata: &CStr) -> Result<(), Error> {
        if self.is_overlay && !self.exists {
            debug!("Creating a new chain {:?}", self.chain.get_str());
            self.chain.set_userdata(userdata);

            batch.add(&self.chain, MsgType::Add);
        }

        for rule in &mut self.rules {
            rule.apply_overlay(batch, userdata)?;
        }

        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.chain, MsgType::Del);
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
    pub rule: Rc<Rule>,
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

        batch.add(&self.rule, MsgType::Add);

        Ok(())
    }

    fn delete_overlay(&mut self, batch: &mut Batch) -> Result<(), Error> {
        if self.is_overlay && self.exists {
            batch.add(&self.rule, MsgType::Del);
        }

        Ok(())
    }
}
