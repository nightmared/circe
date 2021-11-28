use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,

    pub sites: Vec<Site>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Site {
    pub container_name: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub container_ip: Ipv4Addr,
}
