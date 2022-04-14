#![feature(exit_status_error)]
use clap::Arg;

use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{Command, ExitStatusError},
    time::Duration,
};

use thiserror::Error;

use circe_common::{load_config, Challenge, Config, ConfigError};

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
    #[error("Generating the challenge failed")]
    GenerationError(#[from] ExitStatusError),
}

fn save_image(config: &Config, chall: &Challenge, force: bool) -> Result<(), Error> {
    let image_name = format!("circe/{}", chall.name).to_lowercase();
    let src_folder = {
        let mut folder = config.src_folder.clone();
        folder.push(&chall.name);
        folder.push(&chall.offset_directory);
        folder.to_string_lossy().to_string()
    };
    let dest_json_file = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.config.json", chall.name));
        path.to_string_lossy().to_string()
    };
    let dest_squashfs_file = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.sqsh", chall.name));
        path.to_string_lossy().to_string()
    };

    if Path::new(&dest_squashfs_file).exists() && Path::new(&dest_json_file).exists() {
        if !force {
            println!("Image '{}' already exists, ignoring.", image_name);
            return Ok(());
        }
    }

    println!("[+] Building the image '{}'", image_name);

    Command::new("podman")
        .args(["build", "-t", &image_name, &src_folder])
        .spawn()?
        .wait()?
        .exit_ok()?;

    println!("[+] Writing the container configuration to a dedicated JSON file");
    let json = Command::new("podman")
        .args([
            "inspect",
            "-f",
            "{{json .Config}}",
            "-t",
            "image",
            &image_name,
        ])
        .output()?;
    json.status.exit_ok()?;

    File::create(&dest_json_file)?.write_all(&json.stdout)?;

    println!("[+] Generating a squashfs image of the file system");

    Command::new("podman")
        .args([
            "unshare",
            "circe_launcher/mksquashfs.sh",
            &image_name,
            &dest_squashfs_file,
        ])
        .spawn()?
        .wait()?;

    println!(
        "[+] Done, the image for challenge '{}' was saved!",
        image_name
    );

    Ok(())
}

fn main() -> Result<(), Error> {
    let config = load_config()?;

    let chall_name = Arg::new("challenge_name")
        .long("challenge")
        .short('c')
        .help("Name of the target challenge")
        .multiple_values(true)
        .takes_value(true);

    let app = clap::Command::new("circe_save")
        .author("Simon Thoby <git@nightmared.fr>")
        .version("0.1.0")
        .arg(
            Arg::new("force")
                .long("force")
                .short('f')
                .help("Regenerate even existing images"),
        )
        .arg(chall_name);

    let matches = app.get_matches();

    let to_save: Vec<&Challenge> = if let Some(chall_names) = matches.values_of("challenge_name") {
        let chall_names: Vec<&str> = chall_names.collect();
        config
            .challenges
            .iter()
            .filter(|(chall_name, _)| chall_names.contains(&chall_name.as_str()))
            .map(|(_, challenge)| challenge)
            .collect()
    } else {
        config.challenges.values().collect()
    };

    let mut successes = 0;
    let mut failures = 0;
    for chall in to_save {
        match save_image(&config, chall, matches.is_present("force")) {
            Ok(()) => successes += 1,
            Err(e) => {
                failures += 1;
                match e {
                    Error::GenerationError(_) => eprintln!(
                        "Generation of the image of challenge '{}' failed",
                        chall.name
                    ),
                    e => eprintln!(
                        "An error occured whil processing the challenge '{}': {:?}",
                        chall.name, e
                    ),
                }
            }
        }
    }
    println!("Result: {} successes, {} failures", successes, failures);
    Ok(())
}
