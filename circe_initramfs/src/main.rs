use ipnetwork::Ipv4Network;
use nasty_network_ioctls::{interface_set_ip, interface_set_up};
use nix::fcntl::{readlink, OFlag};
use nix::mount::{mount, umount, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chdir, chroot, execve, fork, mkdir, setsid, ForkResult};
use std::ffi::NulError;
use std::ffi::{CStr, CString};
use std::fs::{create_dir, remove_dir, remove_dir_all, remove_file, File};
use std::net::Ipv4Addr;
use std::panic::catch_unwind;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

use serde_derive::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct DockerImageManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DockerImageConfig {
    #[serde(rename = "Cmd")]
    cmd: Vec<String>,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DockerImage {
    config: DockerImageConfig,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O operation or OS error")]
    OSError(#[from] std::io::Error),
    #[error("Nix error")]
    NixError(#[from] nix::Error),
    #[error("String conversion error")]
    StrError(#[from] NulError),
    #[error("Ip network conversion error")]
    IpNetworkError(#[from] ipnetwork::IpNetworkError),
    #[error("Cannot parse the cmdline as integer")]
    IntConversionError(#[from] std::num::ParseIntError),
    #[error("Could not perform an HTTP query")]
    QueryError(#[from] ureq::Error),
    #[error("cannot read json files from docker")]
    DockerParsingError(#[from] serde_json::Error),
}

const TMP_TAR_PATH: &'static str = "/tmp/container_setup";
const CONTAINER_PATH: &'static str = "/container";
const ROOTFS_PATH: &'static str = "/container/rootfs";

fn setup_term(kmsg: bool) -> Result<(), Error> {
    let console_fd = nix::fcntl::open(
        if kmsg { "/dev/kmsg" } else { "/dev/ttyS0" },
        OFlag::O_RDWR,
        Mode::empty(),
    )?;
    nix::unistd::dup2(console_fd, 0)?;
    nix::unistd::dup2(console_fd, 1)?;
    nix::unistd::dup2(console_fd, 2)?;
    nix::unistd::close(console_fd)?;

    println!("[+] Changed the input/output file descriptor");

    Ok(())
}

fn send_ping(source: Ipv4Addr, gateway: Ipv4Addr) -> ! {
    loop {
        let res = catch_unwind(|| -> Result<(), Error> {
            let socket = std::net::UdpSocket::bind(std::net::SocketAddrV4::new(source, 999))?;
            socket.connect(std::net::SocketAddrV4::new(gateway, 666))?;
            socket.send(b"ping")?;

            Ok(())
        });
        std::thread::sleep(std::time::Duration::new(5, 0));
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => println!("[x] sending a ping failed: {:?}", e),
            Err(e) => println!("[x] the ping sender panic()ed: {:?}", e),
        }
    }
}

fn move_dir(source: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<(), Error> {
    let mut dest_dir = dest.as_ref().to_owned();
    // we strip the prefix otherwise push() **replaces** the path instead of concatenating to it
    dest_dir.push(source.as_ref().strip_prefix("/").unwrap());
    std::fs::create_dir(&dest_dir)?;

    for entry in std::fs::read_dir(source.as_ref())? {
        let entry = entry?;

        let mut new_dest = dest_dir.clone();
        new_dest.push(entry.file_name());

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            move_dir(&entry.path(), &new_dest)?;
        } else if file_type.is_symlink() {
            std::os::unix::fs::symlink(readlink(&entry.path())?, &new_dest)?;
        } else if file_type.is_file() {
            std::fs::copy(&entry.path(), &new_dest)?;
        }
    }

    std::fs::remove_dir_all(source.as_ref())?;

    Ok(())
}

fn main() -> Result<(), Error> {
    if std::process::id() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "This program can only be run as pid 1 !",
        )
        .into());
    }

    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    // redirect output to the kernel console (should also appear on the serial device)
    setup_term(true)?;

    println!("[*] Hello and welcome to circe-initramfs");
    println!("[+] copying the content of the initramfs to /newfs");

    // move to a new ramfs, because we cannot pivot_root() on the initramfs, and runc needs it
    create_dir("/newfs")?;
    mount(
        None::<&str>,
        "/newfs",
        Some("ramfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    move_dir("/bin", "/newfs")?;
    move_dir("/sbin", "/newfs")?;
    remove_file("/init")?;
    remove_dir("/root")?;

    println!("[+] moving /newfs over / to become our new rootfs");

    nix::unistd::close(0)?;
    nix::unistd::close(1)?;
    nix::unistd::close(2)?;

    umount("/dev")?;
    remove_dir_all("/dev")?;

    chdir("/newfs")?;

    mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)?;

    chroot(".")?;
    chdir("/")?;

    // setup a new /dev mount
    std::fs::create_dir("/dev")?;
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    setup_term(true)?;

    println!("[+] mounting everything you might expect in a linux system");

    mkdir(
        "/sys",
        Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IROTH | Mode::S_IXOTH,
    )?;
    mkdir(
        "/proc",
        Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IROTH | Mode::S_IXOTH,
    )?;
    mkdir("/tmp", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;

    let mount_flags =
        MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOATIME;
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        mount_flags,
        None::<&str>,
    )?;
    mount(
        None::<&str>,
        "/proc",
        Some("proc"),
        mount_flags,
        None::<&str>,
    )?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        mount_flags,
        None::<&str>,
    )?;

    println!("[+] setting up the network");

    let mut ip = None;
    let mut challenge = None;
    let mut server_port = None;
    for v in std::fs::read_to_string("/proc/cmdline")?.split(" ") {
        if v.starts_with("ip=") {
            ip = Some(Ipv4Network::from_str(&v[3..].trim()).unwrap());
        }
        if v.starts_with("challenge=") {
            challenge = Some(v[10..].to_string());
        }
        if v.starts_with("port=") {
            server_port = Some(u16::from_str(&v[5..])?);
        }
    }

    let tar_file = match (ip, challenge, server_port) {
        (Some(ip), Some(challenge), Some(server_port)) => {
            interface_set_ip("eth0", ip).unwrap();
            interface_set_up("eth0", true).unwrap();

            println!("[+] downloading the container image");

            let gateway = ip.nth(1).unwrap();

            std::thread::spawn(move || -> ! { send_ping(ip.ip(), gateway) });

            let req_path = format!(
                "http://{}:{}/challenges/{}.tar",
                gateway, server_port, challenge,
            );
            ureq::get(&req_path).call()?
        }
        _ => panic!("Missing IP address/port/challenge was supplied, cannot phone home!"),
    };

    // setup the dirs that will hold the container data
    std::fs::create_dir(CONTAINER_PATH)?;
    std::fs::create_dir(ROOTFS_PATH)?;
    // setup the temporary dir for the extraction of the image
    std::fs::create_dir(TMP_TAR_PATH)?;

    println!("[+] extracting the main image");

    let tar_reader = tar_file.into_reader();
    let mut archive = tar::Archive::new(tar_reader);
    archive.unpack(TMP_TAR_PATH)?;

    let manifest = {
        let res: Vec<DockerImageManifest> =
            serde_json::from_reader(File::open(&format!("{}/manifest.json", TMP_TAR_PATH))?)?;

        if res.len() != 1 {
            println!("Couldn't parse the manifest file, did you use a multi-container archive?");
        }

        res[0].clone()
    };

    let image_config: DockerImage = serde_json::from_reader(File::open(&format!(
        "{}/{}",
        TMP_TAR_PATH, manifest.config
    ))?)?;

    // extract all the layers in the rootfs folder
    for layer_archive in &manifest.layers {
        println!("[+] extracting the layer {}", layer_archive);
        let mut archive =
            tar::Archive::new(File::open(&format!("{}/{}", TMP_TAR_PATH, layer_archive))?);
        archive.unpack(ROOTFS_PATH)?;
    }

    // cleanup for keeping our memory footprint as small as possible
    std::fs::remove_dir_all(TMP_TAR_PATH)?;

    println!("[+] spawing a shell");

    if let ForkResult::Child = unsafe { fork()? } {
        let mut cmd = Vec::new();
        if let Some(v) = image_config.config.entrypoint {
            for arg in v {
                cmd.push(CString::new(arg)?);
            }
        }
        for arg in image_config.config.cmd {
            cmd.push(CString::new(arg)?);
        }

        println!("[+] chrooting into the «container»");

        chdir(ROOTFS_PATH)?;
        chroot(".")?;
        chdir("/")?;

        println!("[+] launching the «container» with args {:?}", cmd);

        let console_fd = nix::fcntl::open("/logs", OFlag::O_CREAT | OFlag::O_RDWR, Mode::empty())?;
        nix::unistd::dup2(console_fd, 0)?;
        nix::unistd::dup2(console_fd, 1)?;
        nix::unistd::dup2(console_fd, 2)?;
        nix::unistd::close(console_fd)?;

        execve(cmd[0].as_c_str(), &cmd, &[] as &[&CStr])?;
    }

    if let ForkResult::Child = unsafe { fork()? } {
        setsid()?;
        // open the serial device and make it the controlling terminal
        setup_term(false)?;

        let sh_path = CStr::from_bytes_with_nul(b"/bin/sh\0").unwrap();
        nix::unistd::execve(sh_path, &[sh_path], &[] as &[&CStr; 0])?;
    }

    loop {
        if let Err(e) = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(-1), None) {
            if e == nix::Error::from_errno(nix::errno::Errno::ECHILD) {
                break;
            }
            panic!("{:?}", e);
        }
    }

    unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    Ok(())
}
