use std::ffi::CStr;

use circe_common::load_config;
use circe_common::Challenge;
use circe_common::ConfigError;

use clap::App;
use clap::Arg;
use nix::unistd::execvp;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O operation or OS error")]
    OSError(#[from] std::io::Error),

    #[error("Could not perform an HTTP query")]
    QueryError(#[from] ureq::Error),

    #[error("Could not deserialize the challenge metadata")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Could not load the CIRCE configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("The challenge does not exist")]
    ChallengeDoesNotExist,

    #[error("This challenge does not have a PTS yet, maybe it is not started ?")]
    NoPtsDefined,

    #[error("Could not convert some string to a CStr")]
    FFIError(#[from] std::ffi::FromBytesWithNulError),
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
        let chall_data = serde_json::from_reader::<_, Challenge>(
            ureq::get(&format!(
                "http://{}:{}/challenges/{}/config",
                config.network.ip(),
                config.listening_port,
                challenge_name
            ))
            .call()?
            .into_reader(),
        )?;

        match chall_data.serial_pts {
            Some(pts) => {
                let mut pts = pts.into_bytes();
                pts.push(b'\0');

                execvp(
                    CStr::from_bytes_with_nul(b"minicom\0")?,
                    &[
                        CStr::from_bytes_with_nul(b"minicom\0")?,
                        CStr::from_bytes_with_nul(b"-D\0")?,
                        CStr::from_bytes_with_nul(pts.as_slice())?,
                    ],
                )
                .expect("Couldn't launch minicon");
            }
            None => return Err(Error::NoPtsDefined),
        }
    }

    Ok(())
}
