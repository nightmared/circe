// The network part of this crate is "inspired" from https://raw.githubusercontent.com/mullvad/mullvadvpn-app/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs
use std::fmt::Debug;
use std::net::SocketAddr;

use circe_common::load_config;
use circe_common::Config;
use circe_common::ConfigError;
use hyper::body::HttpBody;
use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::OnceCell;
use tokio::io::BufStream;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;
use tracing::error;

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

    #[error("Error while performing a network operation")]
    NetworkError(#[source] std::io::Error),

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
}

fn setup_network(conf: &Config) -> Result<(), Error> {
    setup_bridge(&conf)?;

    setup_nat(&conf)
}

static GLOBAL_CONFIG: OnceCell<Mutex<Config>> = OnceCell::new();

async fn handle_http_query(req: Request<Body>) -> Result<Response<Body>, ServerError> {
    let (parts, mut body) = req.into_parts();
    let path = parts.uri.path();
    let uri_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut res = Response::new(Body::from("Unknown URL"));
    *res.status_mut() = StatusCode::NOT_FOUND;

    // no router for us
    if uri_parts.len() != 3 || uri_parts[0] != "challenges" {
        return Ok(res);
    }

    let challenge_name: String = String::from_utf8(
        uri_parts[1]
            .bytes()
            // sanity/security (protect against path traversal)
            .filter(|c| b"abcdefghijklmnopqrstuvwxyz0123456789_-".contains(c))
            .collect(),
    )
    .unwrap();
    let mut conf = GLOBAL_CONFIG
        .get()
        .expect("the global configuration is not initialized")
        .lock()
        .await;
    let chall = match conf.challenges.get_mut(&challenge_name) {
        Some(x) => x,
        None => {
            *res.body_mut() = Body::from("Unavailable challenge");
            return Ok(res);
        }
    };

    match uri_parts[2] {
        "docker_config" => {
            let mut file_path = conf.image_folder.clone();
            file_path.push(&format!("{}.docker_config.json", challenge_name));
            match tokio::fs::File::open(file_path).await {
                Ok(fd) => {
                    let body = Body::wrap_stream(ReaderStream::new(BufStream::new(fd)));
                    return Ok(Response::new(body));
                }
                Err(_) => {
                    *res.body_mut() =
                        Body::from("Couldn't find the docker configuration file for the challenge");
                    return Ok(res);
                }
            }
        }
        "config" => {
            let body = Body::from(serde_json::to_vec(chall)?);
            return Ok(Response::new(body));
        }
        "serial_device" => {
            if let Some(Ok(dev)) = body.data().await {
                let serial_pts = String::from_utf8(dev.to_vec())?;
                println!(
                    "{} defined as the pts backend for container image {}",
                    serial_pts, challenge_name
                );
                chall.serial_pts = Some(serial_pts);
            }
        }
        _ => {}
    }

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init the tracing subsystem
    tracing_subscriber::fmt::init();

    let config = load_config()?;
    GLOBAL_CONFIG.set(Mutex::new(config.clone())).unwrap();

    setup_network(&config)?;

    let make_service =
        make_service_fn(|_conn| async { Ok::<_, ServerError>(service_fn(handle_http_query)) });

    let server = Server::bind(&SocketAddr::from((
        config.network.ip(),
        config.listening_port,
    )))
    .serve(make_service);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }

    Ok(())
}
