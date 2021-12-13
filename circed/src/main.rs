// The network part of this crate is "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::fmt::Debug;

use tracing::error;
use warp::Filter;

use circe_common::{load_config, Challenge, Config, ConfigError};

mod network;
use network::{setup_bridge, setup_nat};

mod ruleset;

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

    #[error("Error while performing a network Operation")]
    NetworkError(#[source] std::io::Error),

    #[error("String contains null bytes")]
    NullBytesError(#[from] std::ffi::NulError),

    #[error("This user couldn't be found")]
    UnknownUser,
}

fn setup_network(conf: Config) -> Result<(), Error> {
    let interfaces = setup_bridge(&conf)?;

    setup_nat(&conf, interfaces)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    let config = load_config()?;

    setup_network(config.clone())?;

    let serve_containers = warp::path("challenges")
        .and(warp::path::param())
        .and(warp::path::path("image"))
        .map(|container_name: String| format!("Hi {}", container_name));

    warp::serve(serve_containers)
        .run((config.network.ip(), config.listening_port))
        .await;

    Ok(())
}
