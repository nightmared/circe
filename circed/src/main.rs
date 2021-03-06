// The network part of this crate is "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::SystemTime;

use circe_common::{
    load_config, AuthenticatedQuery, Challenge, ChallengeQuery, ChallengeQueryKind, CirceQuery,
    CirceQueryRaw, CirceResponse, CirceResponseError, ClientQuery, Config, ConfigError,
    DockerImageConfig, InitramfsQuery,
};
use nix::unistd::{chown, User};
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::error;

mod network;
use network::{setup_interfaces, setup_nat};

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

    #[error("Internal error")]
    InternalError(#[from] Error),
}

static GLOBAL_CONFIG: OnceCell<RwLock<Config>> = OnceCell::new();

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
        // todo: optimize this to be read-mostly
        .write()
        .await;
    let chall = match conf.challenges.get_mut(challenge_name) {
        Some(x) => x,
        None => {
            sock.write_all(
                serde_json::to_vec(&CirceResponse::<()>::Error(
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
            chall.running = true;
        }
        ChallengeQueryKind::Initramfs(InitramfsQuery::ShuttingDown) => {
            chall.last_seen_available = None;
            chall.running = false;
            chall.serial_pts = None;
        }
        ChallengeQueryKind::Client(ClientQuery::RetrieveDockerConfig) => {
            let mut file_path = conf.image_folder.clone();
            file_path.push(&format!("{}.config.json", challenge_name));
            let mut docker_config_raw = Vec::new();
            File::open(file_path)
                .await?
                .read_to_end(&mut docker_config_raw)
                .await?;
            let docker_config: DockerImageConfig = serde_json::from_slice(&docker_config_raw)?;
            sock.write_all(
                serde_json::to_vec(&CirceResponse::SuccessWithData(docker_config))?.as_slice(),
            )
            .await?;
            return Ok(());
        }
        ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata) => {
            if remote.ip() != chall.container_ip && !authenticated {
                sock.write_all(
                    serde_json::to_vec(&CirceResponse::<Challenge>::Error(
                        CirceResponseError::Unauthorized,
                    ))?
                    .as_slice(),
                )
                .await?;
                return Ok(());
            }
            sock.write_all(
                serde_json::to_vec(&CirceResponse::SuccessWithData(chall.clone()))?.as_slice(),
            )
            .await?;
            return Ok(());
        }
        ChallengeQueryKind::Client(ClientQuery::SetSerialTerminal(ref term)) => {
            chall.running = true;
            if chall.serial_pts.as_ref() != Some(term) {
                println!(
                    "{} defined as the pts backend for container image {}",
                    term, challenge_name
                );
                chall.serial_pts = Some(term.to_string());
            }
        }
    }

    sock.write_all(serde_json::to_vec(&CirceResponse::<()>::Success)?.as_slice())
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
        CirceQueryRaw::RetrieveChallengeList => {
            let conf = GLOBAL_CONFIG
                .get()
                .expect("the global configuration is not initialized")
                .read()
                .await;
            sock.write_all(
                serde_json::to_vec(&CirceResponse::SuccessWithData(
                    conf.challenges
                        .keys()
                        .map(String::clone)
                        .collect::<Vec<String>>(),
                ))?
                .as_slice(),
            )
            .await?;

            Ok(())
        }
        CirceQueryRaw::ReloadConfig => {
            println!("Configuration reloading asked!");

            let new_conf = load_config().map_err(Error::from)?;
            *GLOBAL_CONFIG
                .get()
                .expect("the global configuration is not initialized")
                .write()
                .await = new_conf;

            let conf = GLOBAL_CONFIG
                .get()
                .expect("the global configuration is not initialized")
                .read()
                .await;
            apply_config(&conf)?;

            sock.write_all(serde_json::to_vec(&CirceResponse::<()>::Success)?.as_slice())
                .await?;

            Ok(())
        }
    }
}

async fn handle_query(sock: &mut TcpStream, remote: SocketAddr) -> Result<(), ServerError> {
    let mut buf = Vec::new();
    if let Err(_) = sock.read_to_end(&mut buf).await {
        sock.write_all(
            serde_json::to_vec(&CirceResponse::<()>::Error(
                CirceResponseError::NetworkError,
            ))?
            .as_slice(),
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
                .read()
                .await;

            // we compare the sha256 hash because this reduces the impact of many
            // potential security issues (like variable-time string comparisons)
            if Sha256::digest(auth_key.as_bytes()) != Sha256::digest(conf.symmetric_key.as_bytes())
            {
                sock.write_all(
                    serde_json::to_vec(&CirceResponse::<()>::Error(
                        CirceResponseError::WrongAuthKey,
                    ))?
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

async fn handle_query_wrapper(mut sock: TcpStream, remote: SocketAddr) {
    let res = handle_query(&mut sock, remote).await;

    if let Err(e) = res {
        println!("[x] got error: {:?}", e);
        sock.write_all(
            serde_json::to_vec(&CirceResponse::<()>::Error(CirceResponseError::ServerError))
                .expect("Could not serialize the error message")
                .as_slice(),
        )
        .await
        .expect("Could not forward the error messageback to the client");
    }

    sock.shutdown()
        .await
        .expect("Could not shutdown the connection");
}

fn apply_config(config: &Config) -> Result<(), Error> {
    println!("Applying the network configuration");

    setup_interfaces(config)?;

    setup_nat(config)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    let config = load_config()?;

    let qmp_folder = Path::new(&config.qmp_folder);
    if !qmp_folder.exists() {
        std::fs::create_dir(qmp_folder).expect("Couldn't create the QMP folder");
    }
    chown(
        qmp_folder,
        Some(
            User::from_name(&config.user)?
                .expect("There should be a user with this name")
                .uid,
        ),
        None,
    )?;

    GLOBAL_CONFIG.set(RwLock::new(config.clone())).unwrap();

    apply_config(&config)?;

    let listener = TcpListener::bind(&SocketAddr::V4(config.get_server_address())).await?;

    loop {
        if let Ok((socket, remote_addr)) = listener.accept().await {
            tokio::spawn(async move {
                // Process each socket concurrently.
                handle_query_wrapper(socket, remote_addr).await
            });
        }
    }
}
