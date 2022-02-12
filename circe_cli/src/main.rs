use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::process::Command;

use circe_common::load_config;
use circe_common::Challenge;
use circe_common::ChallengeQuery;
use circe_common::ChallengeQueryKind;
use circe_common::CirceQueryRaw;
use circe_common::CirceResponseData;
use circe_common::ClientQuery;
use circe_common::ConfigError;
use circe_common::QueryError;

use circe_common::perform_authenticated_query;
use clap::App;
use clap::Arg;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not perform a network request")]
    QueryError(#[from] QueryError),

    #[error("Could not load the CIRCE configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("This challenge does not have a PTS yet, maybe it is not started ?")]
    NoPtsDefined,
}

fn main() -> Result<(), Error> {
    let config = load_config()?;

    let chall_name = Arg::new("challenge_name")
        .long("challenge")
        .short('c')
        .help("Name of the target challenge")
        .takes_value(true)
        .required(true);

    let matches = App::new("circe_cli")
        .author("Simon Thoby <git@nightmared.fr>")
        .version("0.1.0")
        .subcommand(App::new("attach").arg(chall_name))
        .get_matches();

    if let Some(("attach", submatch)) = matches.subcommand() {
        let challenge_name = submatch.value_of("challenge_name").unwrap();

        // query the serial_pts status of the challenge
        if let CirceResponseData::ChallengeMetadata(Challenge {
            serial_pts: Some(pts_path),
            ..
        }) = perform_authenticated_query(
            &SocketAddr::V4(SocketAddrV4::new(
                config.network.nth(1).unwrap(),
                config.listening_port,
            )),
            CirceQueryRaw::Challenge(ChallengeQuery {
                kind: ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata),
                challenge_name: challenge_name.to_string(),
            }),
            config.symmetric_key,
        )? {
            Command::new("minicom")
                .args(&["-D", pts_path.as_str()])
                .status()
                .expect("Couldn't launch minicon");
        } else {
            return Err(Error::NoPtsDefined);
        }
    }

    Ok(())
}
