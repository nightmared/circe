// The network part of this crate is "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::net::SocketAddr;
use std::ptr::null;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Once;
use std::{convert::Infallible, fmt::Debug, sync::Arc};

use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use hyper::{Body, Request, Response, StatusCode};
use lazy_static::lazy_static;
use tokio::io::{BufReader, BufStream};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;
use tracing::error;

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

#[derive(thiserror::Error, Debug)]
pub enum ServerError {}

fn setup_network(conf: &Config) -> Result<(), Error> {
    setup_bridge(&conf)?;

    setup_nat(&conf)
}

lazy_static! {
    static ref GLOBAL_CONFIG: RwLock<Config> = RwLock::new(Config::default());
}

/*
async fn handle_http_query(req: Request<Body>) -> Result<Response<Body>, ServerError> {
    let (parts, _body) = req.into_parts();
    let path = parts.uri.path();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if parts.len() == 3 {
        if parts[0] == "challenges" && parts[2] == "image" {
            let challenge_name: String = String::from_utf8(
                parts[1]
                    .bytes()
                    // sanity/security
                    .filter(|c| b"abcdefghijklmnopqrstuvwxyz0123456789_-".contains(c))
                    .collect(),
            )
            .unwrap();
            let mut file_path = GLOBAL_CONFIG.read().await.image_folder.clone();
            file_path.push(&format!("{}.tar", challenge_name));
            println!("{:?}", file_path);
            match tokio::fs::File::open(file_path).await {
                Ok(fd) => {
                    let body = Body::wrap_stream(ReaderStream::new(BufStream::new(fd)));
                    return Ok(Response::new(body));
                }
                Err(_) => {
                    let mut res = Response::new(Body::from("Unavailable image"));

                    *res.status_mut() = StatusCode::NOT_FOUND;
                    return Ok(res);
                }
            }
        }
    }
    let mut res = Response::new(Body::from("Unknown URL"));

    *res.status_mut() = StatusCode::NOT_FOUND;

    Ok(res)
}
*/

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    let config = load_config()?;
    *GLOBAL_CONFIG.write().await = config.clone();

    setup_network(&config)?;

    /*
    let make_service =
        make_service_fn(|_conn| async { Ok::<_, ServerError>(service_fn(handle_http_query)) });

    /*
    let serve_containers = warp::path("challenges")
        .and(warp::path::param())
        .and(warp::path::path("image"))
        .map(|challenge_name: String| async {
            warp::fs::file("/tmp/a")
        });
        */

    let server = Server::bind(&SocketAddr::from((
        config.network.ip(),
        config.listening_port,
    )))
    .serve(make_service);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    */

    Ok(())
}
