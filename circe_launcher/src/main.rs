#![feature(path_try_exists)]

use qapi::Qmp;
use std::{os::unix::net::UnixStream, process::Command, thread};
use thiserror::Error;

use circe_common::{load_config, ConfigError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O operation or OS error")]
    OSError(#[from] std::io::Error),
    #[error("Could not perform an HTTP query")]
    QueryError(#[from] ureq::Error),
    #[error("Could not load the CIRCE configuration")]
    ConfigurationError(#[from] ConfigError),
    #[error("circed_launcher was not launched with the right amount of arguments")]
    InvalidArgumentNumber,
    #[error("The challenge does not exist")]
    ChallengeDoesNotExist,
    #[error("There is multiple challenges with the same container name")]
    MultipleChallengesWithIdenticalName,
    #[error("Couldn't communicate with QEMU")]
    QMPError(#[from] qapi::ExecuteError),
}

fn main() -> Result<(), Error> {
    let config = load_config()?;

    let args = std::env::args();
    if args.len() != 2 {
        return Err(Error::InvalidArgumentNumber);
    }
    let container_name = args.skip(1).next().unwrap();
    let matching_challenges: Vec<_> = config
        .challenges
        .iter()
        .enumerate()
        .filter(|(_pos, chall)| chall.container_name == container_name)
        .collect();

    if matching_challenges.len() == 0 {
        return Err(Error::ChallengeDoesNotExist);
    } else if matching_challenges.len() > 1 {
        return Err(Error::MultipleChallengesWithIdenticalName);
    }

    let (chall_number, chall) = &matching_challenges[0];

    // generate unique MAC addresses
    let mut macaddr = String::from("66:60");
    for octet in chall.container_ip.octets() {
        macaddr.push_str(&format!(":{:02x}", octet));
    }

    let qmp_path = &format!("/tmp/circe-qmp-{}", chall.container_name);

    // delete stale socket files
    let _ = std::fs::remove_file(&qmp_path);

    let mut cmd = Command::new("qemu-system-x86_64")
        .arg("-enable-kvm")
        .args(["-cpu", "host"])
        .args(["-kernel", "out/kernel-image"])
        .args(["-initrd", "out/initramfs.cpio"])
        .args([
            "-append",
            &format!(
                "'earlyprintk=serial,ttyS0,115200 console=ttyS0,115200 {}'",
                //"' {}'",
                format!(
                    "ip={}/{} port={} challenge={}",
                    chall.container_ip,
                    config.network.prefix(),
                    config.listening_port,
                    chall.container_name
                )
            ),
        ])
        .args(["-m", &format!("{}M", chall.memory_allocation)])
        .args(["-net", &format!("nic,model=virtio,macaddr={}", macaddr)])
        .args([
            "-net",
            &format!(
                "tap,ifname={}-tap{},script=no,downscript=no",
                config.bridge_name, chall_number
            ),
        ])
        // ensure we provide sufficient randomness to the VMs
        .args(["-device", "virtio-rng-pci"])
        .args([
            "-chardev",
            &format!("socket,id=qmp,path={},server=on,wait=off", qmp_path),
        ])
        .args(["-mon", "chardev=qmp,mode=control"])
        .arg("-nographic")
        .args([
            "-serial",
            &format!("file:/tmp/circe-log-{}", chall.container_name),
            // we will switch to a pty once we find out how to make that work (again)
            //"pty",
        ])
        .spawn()?;

    while std::fs::try_exists(qmp_path)? != true {}

    if let Err(e) = (move || -> Result<(), Error> {
        let sock = UnixStream::connect(qmp_path)?;

        let mut qmp = Qmp::from_stream(&sock);

        qmp.handshake()?;

        for dev in qmp.execute(&qapi::qmp::query_chardev {})? {
            if dev.label == "serial0" {
                println!(
                    "The serial device is '{}'",
                    dev.filename, //.splitn(2, ':').skip(1).next().unwrap()
                );
            }
        }

        Ok(())
    })() {
        let _ = cmd.kill();
        return Err(e);
    }

    cmd.wait()?;

    Ok(())
}
