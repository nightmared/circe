#![feature(exit_status_error)]

use std::{
    fs::File,
    io::Write,
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

fn save_image(config: &Config, chall: &Challenge) -> Result<(), Error> {
    let image_name = format!("circe/{}", chall.name).to_lowercase();

    println!("[+] Building the image '{}'", image_name);
    let src_folder = {
        let mut folder = config.src_folder.clone();
        folder.push(&chall.name);
        folder.to_string_lossy().to_string()
    };
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

    let dest_json_file = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.config.json", chall.name));
        path.to_string_lossy().to_string()
    };
    File::create(&dest_json_file)?.write_all(&json.stdout)?;

    println!("[+] Generating a squashfs image of the file system");
    let dest_squashfs_file = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.sqsh", chall.name));
        path.to_string_lossy().to_string()
    };
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

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        println!("No challenge name given, rebuilding all the challenge images!");
        println!("Abort now if this was not your intent, you have 5 seconds...");
        std::thread::sleep(Duration::new(5, 0));
        let mut successes = 0;
        let mut failures = 0;
        for chall in config.challenges.values() {
            match save_image(&config, chall) {
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
    } else if args.len() == 2 {
        let chall = match config.challenges.get(&args[1]) {
            Some(x) => x,
            None => return Err(Error::ChallengeDoesNotExist),
        };

        save_image(&config, chall)
    } else {
        Err(Error::InvalidArgumentNumber)
    }
}
