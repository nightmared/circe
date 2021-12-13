use std::io::Read;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("The configuration file couldn't be loaded")]
    IoError(#[from] std::io::Error),
    #[error("The configuration file couldn't be parsed")]
    ParseError(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,
    pub user: String,

    pub challenges: Vec<Challenge>,
}

fn default_memory_allocation() -> usize {
    // 1GB
    return 1024;
}

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub container_name: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub container_ip: Ipv4Addr,
    #[serde(rename = "memory_in_MB", default = "default_memory_allocation")]
    pub memory_allocation: usize,
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

pub fn load_config() -> Result<Config, ConfigError> {
    // load the configuration
    let mut config_file = std::fs::File::open("config.toml")?;
    let mut config_content = String::with_capacity(5000);
    config_file.read_to_string(&mut config_content)?;
    Ok(toml::from_str(&config_content)?)
}
