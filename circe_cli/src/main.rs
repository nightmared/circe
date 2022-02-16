use std::net::SocketAddr;
use std::net::SocketAddrV4;

use circe_common::load_config;
use circe_common::Challenge;
use circe_common::ChallengeQuery;
use circe_common::ChallengeQueryKind;
use circe_common::CirceQueryRaw;
use circe_common::ClientQuery;
use circe_common::ConfigError;
use circe_common::QueryError;

use circe_common::perform_authenticated_query;
use circe_common::perform_query;
use clap::Arg;
use clap::Command;
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

    let app = Command::new("circe_cli")
        .author("Simon Thoby <git@nightmared.fr>")
        .version("0.1.0")
        .subcommands([
            Command::new("attach")
                .about("Attach to the shell inside a challenge instance")
                .arg(chall_name),
            Command::new("list").about("List the instances and their current states"),
        ])
        .subcommand_required(true);
    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("attach", submatch)) => {
            let challenge_name = submatch.value_of("challenge_name").unwrap();

            // query the serial_pts status of the challenge
            if let Challenge {
                serial_pts: Some(pts_path),
                ..
            } = perform_authenticated_query(
                &SocketAddr::V4(SocketAddrV4::new(
                    config.network.nth(1).unwrap(),
                    config.listening_port,
                )),
                CirceQueryRaw::Challenge(ChallengeQuery {
                    kind: ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata),
                    challenge_name: challenge_name.to_string(),
                }),
                &config.symmetric_key,
            )? {
                std::process::Command::new("minicom")
                    .args(&["-D", pts_path.as_str()])
                    .status()
                    .expect("Couldn't launch minicon");
            } else {
                return Err(Error::NoPtsDefined);
            }
        }
        Some(("list", _)) => {
            let chall_list: Vec<String> = perform_query(
                &config.get_server_address(),
                CirceQueryRaw::RetrieveChallengeList,
            )?;

            for chall in chall_list {
                let chall: Challenge = perform_authenticated_query(
                    &config.get_server_address(),
                    CirceQueryRaw::Challenge(ChallengeQuery {
                        challenge_name: chall,
                        kind: ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata),
                    }),
                    &config.symmetric_key,
                )?;

                println!(
                    "{:35.35} {:15.15} {}",
                    chall.name,
                    chall.container_ip.to_string(),
                    if chall.is_running() { "RUNNING" } else { "OFF" }
                );
            }
        }
        Some((&_, _)) => unreachable!(),
        None => unreachable!(),
    }

    Ok(())
}
