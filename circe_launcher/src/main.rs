#![feature(path_try_exists)]

use qapi::Qmp;
use std::{
    net::{SocketAddr, SocketAddrV4},
    os::unix::net::UnixStream,
    process::Command,
};
use thiserror::Error;

use circe_common::{
    load_config, perform_query_without_response, ChallengeQuery, ChallengeQueryKind, CirceQueryRaw,
    ClientQuery, ConfigError, QueryError,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not perform a network request")]
    QueryError(#[from] QueryError),

    #[error("I/O operation or OS error")]
    OSError(#[from] std::io::Error),

    #[error("Could not load the CIRCE configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("Could not serialize requests")]
    SerializationError(#[from] serde_json::Error),

    #[error("The program was not launched with the right amount of arguments")]
    InvalidArgumentNumber,

    #[error("The challenge does not exist")]
    ChallengeDoesNotExist,

    #[error("Couldn't communicate with QEMU")]
    QMPError(#[from] qapi::ExecuteError),
}

fn main() -> Result<(), Error> {
    let config = load_config()?;

    let args = std::env::args();
    if args.len() != 2 {
        return Err(Error::InvalidArgumentNumber);
    }
    let challenge_name = args.skip(1).next().unwrap();

    let chall = match config.challenges.get(&challenge_name) {
        Some(x) => x,
        None => return Err(Error::ChallengeDoesNotExist),
    };

    let filesystem_path = {
        let mut path = config.image_folder.clone();
        path.push(&format!("{}.sqsh", chall.name));
        path.to_string_lossy().to_string()
    };

    // generate unique MAC addresses
    let mut macaddr = String::from("66:60");
    for octet in chall.container_ip.octets() {
        macaddr.push_str(&format!(":{:02x}", octet));
    }

    let qmp_path = &format!("/tmp/circe-qmp-{}", chall.name);

    // delete stale socket files
    let _ = std::fs::remove_file(&qmp_path);

    let mut cmd = Command::new("qemu-system-x86_64")
        .arg("-enable-kvm")
        .args(["-cpu", "host"])
        .args(["-kernel", "out/kernel-image"])
        //.args(["-kernel", "/boot/vmlinuz-5.16.1-1-default"])
        .args(["-initrd", "out/initramfs.cpio"])
        .args([
            "-drive",
            &format!("file={},if=virtio,readonly=on", &filesystem_path),
        ])
        .args([
            "-append",
            &format!(
                "earlyprintk=serial,ttyS0,115200 console=ttyS0,115200 norandmaps {}",
                format!(
                    "ip={}/{} port={} challenge={}",
                    chall.container_ip,
                    config.network.prefix(),
                    config.listening_port,
                    chall.name
                )
            ),
        ])
        .args(["-m", &format!("{}M", chall.memory_allocation)])
        .args(["-net", &format!("nic,model=virtio,macaddr={}", macaddr)])
        .args([
            "-net",
            &format!("tap,ifname={},script=no,downscript=no", chall.tap_name),
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
            // we will switch to a pty once we find out how to make that work (again)
            //&format!("file:/tmp/circe-log-{}", chall.name),
            "pty",
        ])
        .spawn()?;

    while std::fs::try_exists(qmp_path)? != true {}

    if let Err(e) = (move || -> Result<(), Error> {
        let sock = UnixStream::connect(qmp_path)?;

        let mut qmp = Qmp::from_stream(&sock);

        qmp.handshake()?;

        for dev in qmp.execute(&qapi::qmp::query_chardev {})? {
            if dev.label == "serial0" {
                let serial_device = dev.filename.splitn(2, ':').skip(1).next();
                if let Some(serial_device) = serial_device {
                    println!("The serial device is '{}'", serial_device);
                    // notify the server of the serial device path
                    perform_query_without_response(
                        &SocketAddr::V4(SocketAddrV4::new(
                            config.network.nth(1).unwrap(),
                            config.listening_port,
                        )),
                        CirceQueryRaw::Challenge(ChallengeQuery {
                            kind: ChallengeQueryKind::Client(ClientQuery::SetSerialTerminal(
                                serial_device.to_string(),
                            )),
                            challenge_name: challenge_name.clone(),
                        }),
                    )?;
                }
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
