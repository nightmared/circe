// "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;

use tracing::error;

use circe_common::{Challenge, Config};

mod network;
use network::{setup_bridge, setup_nat};

mod ruleset;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Query error")]
    QueryError(#[from] rustables::query::Error),

    #[error("The target obejct already exists")]
    AlreadyExistsError,

    #[error("The configuration file presents an issue")]
    ConfigurationFileError(#[source] std::io::Error),

    #[error("The configuration couldn't be parsed")]
    ConfigurationParsingError(#[from] toml::de::Error),

    #[error("Error while manipulating UNIX objects")]
    UnixError(#[from] nix::Error),

    #[error("Error while performing a network Operation")]
    NetworkError(#[source] std::io::Error),

    #[error("String contains null bytes")]
    NullBytesError(#[from] std::ffi::NulError),
}

fn setup_network(conf: Config) -> Result<(), Error> {
    let interfaces = setup_bridge(&conf)?;

    setup_nat(&conf, interfaces)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    // load the configuration
    let mut config_file =
        File::open("config.toml").map_err(|x| Error::ConfigurationFileError(x))?;
    let mut config_content = String::with_capacity(5000);
    config_file
        .read_to_string(&mut config_content)
        .map_err(|x| Error::ConfigurationFileError(x))?;
    let config: Config = toml::from_str(&config_content)?;

    setup_network(config.clone())?;

    /*
    warp::serve(hello)
        .run((config.network.ip(), config.listening_port))
        .await;
        */

    Ok(())
}
