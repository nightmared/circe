#[cfg(any(feature = "toml_support", feature = "net"))]
use std::io::Read;
#[cfg(feature = "net")]
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(feature = "net")]
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::SystemTime;
use std::{collections::HashMap, time::Duration};

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
    pub symmetric_key: String,

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
    pub flag: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: Ipv4Network,
    pub bridge_name: String,
    pub listening_port: u16,
    pub user: String,
    pub src_folder: PathBuf,
    pub image_folder: PathBuf,
    pub symmetric_key: String,

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
            symmetric_key: raw.symmetric_key,
            challenges: challs,
        }
    }
}

#[cfg(feature = "net")]
impl Config {
    pub fn get_server_address(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            self.network.nth(1).unwrap(),
            self.listening_port,
        ))
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
    pub flag: String,
    pub serial_pts: Option<String>,
    pub last_seen_available: Option<SystemTime>,
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
            flag: raw.flag,
            serial_pts: None,
            last_seen_available: None,
        }
    }

    pub fn is_running(&self) -> bool {
        match self.last_seen_available {
            Some(time) => time > SystemTime::now() - Duration::new(60, 1),
            None => false,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DockuerVolume {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DockerImageConfig {
    #[serde(rename = "Cmd")]
    pub cmd: Vec<String>,
    #[serde(rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env_variables: Vec<String>,
    #[serde(rename = "WorkingDir")]
    pub work_directory: String,
    #[serde(rename = "Volumes")]
    pub volumes: Option<HashMap<String, DockuerVolume>>,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum InitramfsQuery {
    ServiceAvailable,
    ShuttingDown,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum CirceResponseError {
    InvalidQuery,
    NetworkError,
    ServerError,
    NonExistentChallenge,
    NonExistentConfigFileForChallenge,
    Unauthorized,
    WrongAuthKey,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum ClientQuery {
    RetrieveDockerConfig,
    RetrieveChallengeMetadata,
    SetSerialTerminal(String),
}

#[derive(Deserialize, Serialize, Debug)]
pub enum ChallengeQueryKind {
    Initramfs(InitramfsQuery),
    Client(ClientQuery),
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ChallengeQuery {
    pub kind: ChallengeQueryKind,
    pub challenge_name: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthenticatedQuery<T> {
    pub auth_key: String,
    pub wrapped_query: T,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum CirceQueryRaw {
    Challenge(ChallengeQuery),
    RetrieveChallengeList,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum CirceQuery {
    Raw(CirceQueryRaw),
    AuthenticatedQuery(AuthenticatedQuery<CirceQueryRaw>),
}

#[derive(Deserialize, Serialize, Debug)]
pub enum CirceResponse<T> {
    Success,
    SuccessWithData(T),
    Error(CirceResponseError),
}

#[cfg(feature = "net")]
#[derive(Error, Debug)]
pub enum QueryError {
    #[error("A network error occurred")]
    IoError(#[from] std::io::Error),

    #[error("Serialization Error")]
    SerializationError(#[from] serde_json::Error),

    #[error("Missing data in the returned value")]
    MissingDataError,

    #[error("Received data when non was expected")]
    TooMuchDataError,

    #[error("The server return a custom error")]
    CirceError(CirceResponseError),
}

#[cfg(feature = "net")]
fn perform_raw_query(target_addr: &SocketAddr, val: &CirceQuery) -> Result<Vec<u8>, QueryError> {
    let mut stream = TcpStream::connect(target_addr)?;
    stream.write_all(serde_json::to_vec(val)?.as_slice())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(feature = "net")]
pub fn perform_query_without_response(
    target_addr: &SocketAddr,
    val: CirceQueryRaw,
) -> Result<(), QueryError> {
    let response = perform_raw_query(target_addr, &CirceQuery::Raw(val))?;
    match serde_json::from_slice::<CirceResponse<()>>(&response)? {
        CirceResponse::Success => return Ok(()),
        CirceResponse::SuccessWithData(_) => return Err(QueryError::TooMuchDataError),
        CirceResponse::Error(e) => return Err(QueryError::CirceError(e)),
    }
}

#[cfg(feature = "net")]
pub fn perform_query<T: for<'a> serde::Deserialize<'a>>(
    target_addr: &SocketAddr,
    val: CirceQueryRaw,
) -> Result<T, QueryError> {
    let response = perform_raw_query(target_addr, &CirceQuery::Raw(val))?;
    match serde_json::from_slice(&response)? {
        CirceResponse::Success => return Err(QueryError::MissingDataError),
        CirceResponse::SuccessWithData(data) => return Ok(data),
        CirceResponse::Error(e) => return Err(QueryError::CirceError(e)),
    }
}

#[cfg(feature = "net")]
pub fn perform_authenticated_query<T: for<'a> serde::Deserialize<'a>>(
    target_addr: &SocketAddr,
    val: CirceQueryRaw,
    auth_key: &str,
) -> Result<T, QueryError> {
    let response = perform_raw_query(
        target_addr,
        &CirceQuery::AuthenticatedQuery(AuthenticatedQuery {
            wrapped_query: val,
            auth_key: auth_key.to_string(),
        }),
    )?;
    match serde_json::from_slice(&response)? {
        CirceResponse::Success => return Err(QueryError::MissingDataError),
        CirceResponse::SuccessWithData(data) => return Ok(data),
        CirceResponse::Error(e) => return Err(QueryError::CirceError(e)),
    }
}
