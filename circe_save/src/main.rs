use std::process::Command;

use thiserror::Error;

use circe_common::{load_config, Config, ConfigError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O operation or OS error")]
    OSError(#[from] std::io::Error),
    #[error("Could not load the CIRCE configuration")]
    ConfigurationError(#[from] ConfigError),
    #[error("The program was not launched with the right amount of arguments")]
    InvalidArgumentNumber,
    #[error("The challenge does not exist")]
    ChallengeDoesNotExist,
}

fn main() -> Result<(), Error> {
    let config = load_config()?;

    let args = std::env::args();
    if args.len() != 2 {
        return Err(Error::InvalidArgumentNumber);
    }
    let container_name = args.skip(1).next().unwrap();

    let chall = match config.challenges.get(&container_name) {
        Some(x) => x,
        None => return Err(Error::ChallengeDoesNotExist),
    };

    let image_name = format!("circe/{}", chall.name);

    let src_folder = {
        let mut folder = config.src_folder.clone();
        folder.push(&chall.name);
        folder.to_string_lossy().to_string()
    };
    let mut build = Command::new("podman")
        .args(["build", "-t", &image_name, &src_folder])
        .spawn()?;

    build.wait()?;

    let dest_file = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.sqsh", chall.name));
        path.to_string_lossy().to_string()
    };
    let mut image = Command::new("podman")
        .args([
            "unshare",
            "circe_launcher/mksquashfs.sh",
            &image_name,
            &dest_file,
        ])
        .spawn()?;

    image.wait()?;

    Ok(())
}
