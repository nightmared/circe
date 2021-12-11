use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,

    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub container_name: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub container_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    ReloadFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralInfo {
    pub challenges: Vec<ChallengeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub challenge_file_name: String,
    pub port: u16,
    pub ip: Ipv4Network,
    pub serial_pts: Option<String>,
}
