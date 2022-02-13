// The network part of this crate is "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::SystemTime;

use circe_common::load_config;
use circe_common::AuthenticatedQuery;
use circe_common::ChallengeQuery;
use circe_common::ChallengeQueryKind;
use circe_common::CirceQuery;
use circe_common::CirceQueryRaw;
use circe_common::CirceResponse;
use circe_common::CirceResponseData;
use circe_common::CirceResponseError;
use circe_common::ClientQuery;
use circe_common::Config;
use circe_common::ConfigError;
use circe_common::InitramfsQuery;
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::error;

mod network;
use network::{setup_bridge, setup_nat};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] rustables::query::Error),

    #[error("The target obejct already exists")]
    AlreadyExistsError,

    #[error("Loading the configuration fail")]
    ConfigurationError(#[from] ConfigError),

    #[error("Error while manipulating UNIX objects")]
    UnixError(#[from] nix::Error),

    #[error("Error while performing a network operation")]
    NetworkError(#[from] std::io::Error),

    #[error("String contains null bytes")]
    NullBytesError(#[from] std::ffi::NulError),

    #[error("This user couldn't be found")]
    UnknownUser,
}

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("The byte array contain non-UTF8 characters")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("Could not serialize the challenge metadata")]
    SerializationError(#[from] serde_json::Error),

    #[error("Error while performing a network operation")]
    NetworkError(#[from] std::io::Error),
}

fn setup_network(conf: &Config) -> Result<(), Error> {
    setup_bridge(&conf)?;

    setup_nat(&conf)
}

static GLOBAL_CONFIG: OnceCell<Mutex<Config>> = OnceCell::new();

async fn handle_challenge_query(
    sock: &mut TcpStream,
    remote: SocketAddr,
    kind: ChallengeQueryKind,
    challenge_name: &str,
    authenticated: bool,
) -> Result<(), ServerError> {
    let mut conf = GLOBAL_CONFIG
        .get()
        .expect("the global configuration is not initialized")
        .lock()
        .await;
    let chall = match conf.challenges.get_mut(challenge_name) {
        Some(x) => x,
        None => {
            sock.write_all(
                serde_json::to_vec(&CirceResponse::Error(
                    CirceResponseError::NonExistentChallenge,
                ))?
                .as_slice(),
            )
            .await?;
            return Ok(());
        }
    };

    match kind {
        ChallengeQueryKind::Initramfs(InitramfsQuery::ServiceAvailable) => {
            chall.last_seen_available = Some(SystemTime::now());
        }
        ChallengeQueryKind::Initramfs(InitramfsQuery::ShuttingDown) => {}
        ChallengeQueryKind::Client(ClientQuery::RetrieveDockerConfig) => {
            let mut file_path = conf.image_folder.clone();
            file_path.push(&format!("{}.docker_config.json", challenge_name));
            let mut docker_config_raw = Vec::new();
            File::open(file_path)
                .await?
                .read_to_end(&mut docker_config_raw)
                .await?;
            let docker_config = serde_json::from_slice(&docker_config_raw)?;
            sock.write_all(
                serde_json::to_vec(&CirceResponse::SuccessWithData(
                    CirceResponseData::DockerImageConfig(docker_config),
                ))?
                .as_slice(),
            )
            .await?;
            return Ok(());
        }
        ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata) => {
            if remote.ip() != chall.container_ip && !authenticated {
                sock.write_all(
                    serde_json::to_vec(&CirceResponse::Error(CirceResponseError::Unauthorized))?
                        .as_slice(),
                )
                .await?;
                return Ok(());
            }
            sock.write_all(
                serde_json::to_vec(&CirceResponse::SuccessWithData(
                    CirceResponseData::ChallengeMetadata(chall.clone()),
                ))?
                .as_slice(),
            )
            .await?;
            return Ok(());
        }
        ChallengeQueryKind::Client(ClientQuery::SetSerialTerminal(term)) => {
            println!(
                "{} defined as the pts backend for container image {}",
                term, challenge_name
            );
            chall.serial_pts = Some(term);
        }
    }

    sock.write_all(serde_json::to_vec(&CirceResponse::Success)?.as_slice())
        .await?;
    Ok(())
}

async fn handle_query_raw(
    sock: &mut TcpStream,
    remote: SocketAddr,
    query: CirceQueryRaw,
    authenticated: bool,
) -> Result<(), ServerError> {
    match query {
        CirceQueryRaw::Challenge(ChallengeQuery {
            kind,
            challenge_name,
        }) => {
            let challenge_name: String = String::from_utf8(
                challenge_name
                    .bytes()
                    // sanity/security (protect against path traversal)
                    .filter(|c| b"abcdefghijklmnopqrstuvwxyz0123456789_-".contains(c))
                    .collect(),
            )?;

            handle_challenge_query(sock, remote, kind, &challenge_name, authenticated).await
        }
    }
}

async fn handle_query(sock: &mut TcpStream, remote: SocketAddr) -> Result<(), ServerError> {
    let mut buf = Vec::new();
    if let Err(_) = sock.read_to_end(&mut buf).await {
        sock.write_all(
            serde_json::to_vec(&CirceResponse::Error(CirceResponseError::NetworkError))?.as_slice(),
        )
        .await?;
        return Ok(());
    }
    let query = serde_json::from_slice(&buf)?;
    match query {
        CirceQuery::Raw(raw_query) => handle_query_raw(sock, remote, raw_query, false).await,
        CirceQuery::AuthenticatedQuery(AuthenticatedQuery {
            auth_key,
            wrapped_query,
        }) => {
            let conf = GLOBAL_CONFIG
                .get()
                .expect("the global configuration is not initialized")
                .lock()
                .await;

            // we compare the sha256 hash because this reduces the impact of many
            // potential security issues (like variable-time string comparisons)
            if Sha256::digest(auth_key.as_bytes()) != Sha256::digest(conf.symmetric_key.as_bytes())
            {
                sock.write_all(
                    serde_json::to_vec(&CirceResponse::Error(CirceResponseError::WrongAuthKey))?
                        .as_slice(),
                )
                .await?;
                return Ok(());
            }

            // free the mutex to prevent trying to take it twice and deadlock
            drop(conf);

            handle_query_raw(sock, remote, wrapped_query, true).await
        }
    }
}

async fn handle_query_wrapper(mut sock: TcpStream, remote: SocketAddr) -> Result<(), ServerError> {
    let res = handle_query(&mut sock, remote).await;

    sock.shutdown().await?;

    res
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    let config = load_config()?;
    GLOBAL_CONFIG.set(Mutex::new(config.clone())).unwrap();

    setup_network(&config)?;

    let listener = TcpListener::bind(&SocketAddr::from((
        config.network.nth(1).unwrap(),
        config.listening_port,
    )))
    .await?;

    loop {
        if let Ok((socket, remote_addr)) = listener.accept().await {
            tokio::spawn(async move {
                // Process each socket concurrently.
                handle_query_wrapper(socket, remote_addr).await
            });
        }
    }
}
