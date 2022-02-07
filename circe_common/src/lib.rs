use std::collections::HashMap;
#[cfg(feature = "toml_support")]
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnetwork::Ipv4Network;
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("The configuration file couldn't be loaded")]
    IoError(#[from] std::io::Error),
    #[cfg(feature = "toml_support")]
    #[error("The configuration file couldn't be parsed")]
    ParseError(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawConfig {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,
    pub user: String,
    pub src_folder: String,
    pub image_folder: String,

    pub challenges: Vec<RawChallenge>,
}

fn default_memory_allocation() -> usize {
    // 1GB
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawChallenge {
    pub name: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub container_ip: Ipv4Addr,
    #[serde(rename = "memory_in_MB", default = "default_memory_allocation")]
    pub memory_allocation: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,
    pub user: String,
    pub src_folder: PathBuf,
    pub image_folder: PathBuf,

    // name -> value
    pub challenges: HashMap<String, Challenge>,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        let mut challs = HashMap::with_capacity(raw.challenges.len());

        for (pos, chall) in raw.challenges.into_iter().enumerate() {
            let tap_name = format!("{}-tap{}", raw.bridge_name, pos);
            challs.insert(chall.name.clone(), Challenge::from_raw(chall, tap_name));
        }

        Config {
            network: raw.network,
            bridge_name: raw.bridge_name,
            listening_port: raw.listening_port,
            user: raw.user,
            src_folder: PathBuf::from(raw.src_folder),
            image_folder: PathBuf::from(raw.image_folder),
            challenges: challs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    // both the name of the container and of the challenge
    pub name: String,
    pub tap_name: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub container_ip: Ipv4Addr,
    pub memory_allocation: usize,
    pub serial_pts: Option<String>,
}

impl Challenge {
    fn from_raw(raw: RawChallenge, tap_name: String) -> Self {
        Challenge {
            name: raw.name,
            tap_name,
            source_port: raw.source_port,
            destination_port: raw.destination_port,
            container_ip: raw.container_ip,
            memory_allocation: raw.memory_allocation,
            serial_pts: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    ReloadFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralInfo {
    pub challenges: Vec<Challenge>,
}

#[cfg(feature = "toml_support")]
pub fn load_config() -> Result<Config, ConfigError> {
    // load the configuration
    let mut config_file = std::fs::File::open("config.toml")?;
    let mut config_content = String::with_capacity(5000);
    config_file.read_to_string(&mut config_content)?;

    let raw: RawConfig = toml::from_str(&config_content)?;
    Ok(Config::from(raw))
}

#[derive(Deserialize, Clone, Debug)]
pub struct DockerImageConfig {
    #[serde(rename = "Cmd")]
    pub cmd: Vec<String>,
    #[serde(rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env_variables: Vec<String>,
    #[serde(rename = "WorkingDir")]
    pub work_directory: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum InitramfsMessage {
    Ping,
}
