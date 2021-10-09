// heavily "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use nftnl::{
    nftnl_sys::{NFTNL_RULE_CHAIN, NFTNL_RULE_FAMILY, NFTNL_RULE_TABLE},
    query::list_objects_with_data,
    Chain, ProtoFamily, Rule, Table,
};
use std::{
    convert::TryFrom,
    ffi::{CStr, CString},
};
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] nftnl::query::Error),

    #[error("Couldn't allocate a netlink object, out of memory ?")]
    NetlinkAllocationFailed,
}

lazy_static::lazy_static! {
    static ref IN_CHAIN_NAME: CString = CString::new("input").unwrap();
    static ref OUT_CHAIN_NAME: CString = CString::new("output").unwrap();
    static ref FORWARD_CHAIN_NAME: CString = CString::new("forward").unwrap();
    static ref PREROUTING_CHAIN_NAME: CString = CString::new("prerouting").unwrap();
    static ref NAT_CHAIN_NAME: CString = CString::new("nat").unwrap();
}

pub fn get_tables_cb(
    header: &libc::nlmsghdr,
    (_, tables): &mut (&(), &mut Vec<Table>),
) -> libc::c_int {
    unsafe {
        let table = nftnl::nftnl_sys::nftnl_table_alloc();
        if table as usize == 0 {
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let err = nftnl::nftnl_sys::nftnl_table_nlmsg_parse(header, table);
        if err < 0 {
            error!("Failed to parse nelink table message - {}", err);
            nftnl::nftnl_sys::nftnl_table_free(table);
            return err;
        }
        let family = nftnl::nftnl_sys::nftnl_table_get_u32(
            table,
            nftnl::nftnl_sys::NFTNL_TABLE_FAMILY as u16,
        );
        match ProtoFamily::try_from(family as i32) {
            Ok(family) => {
                tables.push(Table::from_raw(table, family));
                mnl::mnl_sys::MNL_CB_OK
            }
            Err(nftnl::InvalidProtocolFamily) => {
                error!("The netlink table didn't have a valid protocol family !?");
                nftnl::nftnl_sys::nftnl_table_free(table);
                mnl::mnl_sys::MNL_CB_ERROR
            }
        }
    }
}

pub fn get_chains_cb<'a>(
    header: &libc::nlmsghdr,
    (table, chains): &mut (&'a Table, &mut Vec<Chain<'a>>),
) -> libc::c_int {
    unsafe {
        let chain = nftnl::nftnl_sys::nftnl_chain_alloc();
        if chain as usize == 0 {
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let err = nftnl::nftnl_sys::nftnl_chain_nlmsg_parse(header, chain);
        if err < 0 {
            error!("Failed to parse nelink chain message - {}", err);
            nftnl::nftnl_sys::nftnl_chain_free(chain);
            return err;
        }

        let table_name = CStr::from_ptr(nftnl::nftnl_sys::nftnl_chain_get_str(
            chain,
            nftnl::nftnl_sys::NFTNL_CHAIN_TABLE as u16,
        ));
        let family: ProtoFamily = std::mem::transmute(nftnl::nftnl_sys::nftnl_chain_get_u32(
            chain,
            nftnl::nftnl_sys::NFTNL_CHAIN_FAMILY as u16,
        ) as u16);

        if table_name != table.get_name() {
            nftnl::nftnl_sys::nftnl_chain_free(chain);
            return mnl::mnl_sys::MNL_CB_OK;
        }

        if family != ProtoFamily::Unspec && family != table.get_family() {
            nftnl::nftnl_sys::nftnl_chain_free(chain);
            return mnl::mnl_sys::MNL_CB_OK;
        }

        chains.push(Chain::from_raw(chain, table));
    }
    mnl::mnl_sys::MNL_CB_OK
}

pub fn get_rules_cb<'a>(
    header: &libc::nlmsghdr,
    (chain, rules): &mut (&'a Chain<'a>, &mut Vec<Rule<'a>>),
) -> libc::c_int {
    unsafe {
        let rule = nftnl::nftnl_sys::nftnl_rule_alloc();
        let err = nftnl::nftnl_sys::nftnl_rule_nlmsg_parse(header, rule);
        if err < 0 {
            error!("Failed to parse nelink rule message - {}", err);
            nftnl::nftnl_sys::nftnl_rule_free(rule);
            return err;
        }

        rules.push(Rule::from_raw(rule, chain));
    }
    mnl::mnl_sys::MNL_CB_OK
}

fn list_tables() -> Result<Vec<Table>, Error> {
    list_objects_with_data(libc::NFT_MSG_GETTABLE as u16, get_tables_cb, &(), None)
        .map_err(Error::from)
}

fn list_chains_for_table<'a>(table: &'a Table) -> Result<Vec<Chain<'a>>, Error> {
    list_objects_with_data(libc::NFT_MSG_GETCHAIN as u16, get_chains_cb, &table, None)
        .map_err(Error::from)
}

fn list_rules_for_chain<'a>(chain: &'a Chain<'a>) -> Result<Vec<Rule<'a>>, Error> {
    list_objects_with_data(
        libc::NFT_MSG_GETRULE as u16,
        get_rules_cb,
        &chain,
        // only retrieve rules from the currently targetted chain
        Some(&|hdr| unsafe {
            let rule = nftnl::nftnl_sys::nftnl_rule_alloc();
            if rule as usize == 0 {
                return Err(nftnl::query::Error::InitError(Box::new(
                    Error::NetlinkAllocationFailed,
                )));
            }

            nftnl::nftnl_sys::nftnl_rule_set_str(
                rule,
                NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            nftnl::nftnl_sys::nftnl_rule_set_u32(
                rule,
                NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );
            nftnl::nftnl_sys::nftnl_rule_set_str(
                rule,
                NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );

            nftnl::nftnl_sys::nftnl_rule_nlmsg_build_payload(hdr, rule);

            nftnl::nftnl_sys::nftnl_rule_free(rule);
            Ok(())
        }),
    )
    .map_err(Error::from)
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let tables = list_tables()?;
    for table in tables {
        let chains = list_chains_for_table(&table)?;
        for chain in chains.iter() {
            println!("chains: {:?}", chain);
            let rules = list_rules_for_chain(&chain)?;
            for rule in rules {
                println!("{:?}", rule.get_str());
            }
        }
    }
    Ok(())
}
