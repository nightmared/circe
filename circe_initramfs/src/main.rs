use std::ffi::NulError;
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::panic::catch_unwind;
use std::path::Path;
use std::str::FromStr;

use ipnetwork::Ipv4Network;
use libc::setenv;
use nasty_network_ioctls::{interface_set_ip, interface_set_up, set_default_route};
use nix::fcntl::OFlag;
use nix::mount::{mount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::stat::Mode;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::{chdir, chroot, execve, execvpe, fork, mkdir, setsid, sleep, ForkResult};
use thiserror::Error;

use circe_common::{
    perform_query, perform_query_without_response, Challenge, ChallengeQuery, ChallengeQueryKind,
    CirceQueryRaw, CirceResponseData, ClientQuery, DockerImageConfig, InitramfsQuery, QueryError,
};

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

    #[error("Could not perform a query")]
    QueryError(#[from] QueryError),

    #[error("Cannot read json files from docker")]
    DockerParsingError(#[from] serde_json::Error),

    #[error("Logic error in the server")]
    InvalidServerResponse,
}

const CONTAINER_PATH: &'static str = "/container";

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

fn send_message_to_manager(
    challenge_name: &str,
    gateway: Ipv4Addr,
    server_port: u16,
    message: InitramfsQuery,
) -> Result<(), QueryError> {
    perform_query_without_response(
        &SocketAddr::V4(SocketAddrV4::new(gateway, server_port)),
        CirceQueryRaw::Challenge(ChallengeQuery {
            kind: ChallengeQueryKind::Initramfs(message),
            challenge_name: challenge_name.to_string(),
        }),
    )
}

fn send_ping(challenge_name: &str, gateway: Ipv4Addr, server_port: u16) -> ! {
    loop {
        let res = catch_unwind(|| {
            send_message_to_manager(
                challenge_name,
                gateway,
                server_port,
                InitramfsQuery::ServiceAvailable,
            )
        });
        std::thread::sleep(std::time::Duration::new(5, 0));
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => println!("[x] sending a ping failed: {:?}", e),
            Err(e) => println!("[x] the ping sender panic()ed: {:?}", e),
        }
    }
}

fn container_process(
    container_path: &Path,
    challenge_metadata: &Challenge,
    config: &mut DockerImageConfig,
    challenge_name: &String,
) -> Result<(), Error> {
    println!("[+] chrooting inside the container");
    chdir(container_path)?;
    chroot(".")?;

    if config.work_directory == "" {
        config.work_directory = String::from("/");
    }

    println!("[+] moving to the directory {}", config.work_directory);
    chdir(Path::new(&config.work_directory))?;

    if let Some(ref volumes) = config.volumes {
        for volume in volumes.keys() {
            if volume.ends_with("flag.txt") {
                println!("[+] flag volume found, writing to the target file path");
                let mut fd = OpenOptions::new().write(true).create(true).open(volume)?;
                fd.write(challenge_metadata.flag.as_bytes())?;
            }
        }
    }

    println!("[+] switching to the log file");
    let console_fd = nix::fcntl::open("/logs", OFlag::O_CREAT | OFlag::O_RDWR, Mode::empty())?;
    nix::unistd::dup2(console_fd, 0)?;
    nix::unistd::dup2(console_fd, 1)?;
    nix::unistd::dup2(console_fd, 2)?;
    nix::unistd::close(console_fd)?;
    setsid()?;

    let mut cmd = Vec::new();
    if let Some(v) = &config.entrypoint {
        for arg in v {
            cmd.push(CString::new(arg.as_bytes())?);
        }
    }
    for arg in &config.cmd {
        cmd.push(CString::new(arg.as_bytes())?);
    }

    let mut env: Vec<CString> = config
        .env_variables
        .iter()
        .map(|x| CString::new(x.as_bytes()))
        .flatten()
        .collect();
    env.push(CString::new(format!("HOSTNAME={}", &challenge_name))?);
    env.push(CString::new(format!("PWD={}", &config.work_directory))?);

    println!(
        "[+] launching the container executable {:?} with environment {:?}",
        cmd, env
    );

    // "execvpe() searches for the program using the value of PATH from the caller's environment, not from the envp argument."
    for val in env.iter() {
        let split_val: Vec<&[u8]> = val.as_bytes().splitn(2, |&b| b == b'=').collect();
        if split_val.len() != 2 {
            println!("Invalid env variable {:?}", val);
            continue;
        }
        if split_val[0] == b"PATH" {
            unsafe {
                setenv(
                    CString::new("PATH")?.as_ptr(),
                    split_val[1].as_ptr() as *const i8,
                    1,
                );
            }
        }
    }
    execvpe(cmd[0].as_c_str(), &cmd, &env)?;

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
    setup_term(false)?;

    println!("[*] Hello and welcome to circe-initramfs");

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
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        mount_flags,
        None::<&str>,
    )?;

    println!("[+] setting up the network");

    let (net, challenge_name, server_port) = {
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

        match (ip, challenge, server_port) {
            (None, _, _) | (_, None, _) | (_, _, None) => {
                panic!("Missing IP address/port/challenge was supplied, cannot phone home!")
            }
            (Some(ip), Some(challenge), Some(server_port)) => (ip, challenge, server_port),
        }
    };

    interface_set_ip("eth0", net)?;
    interface_set_up("eth0", true)?;

    let gateway = net.nth(1).unwrap();

    set_default_route(gateway)?;

    {
        let challenge_name = challenge_name.clone();
        std::thread::spawn(move || -> ! { send_ping(&challenge_name, gateway, server_port) });
    }

    println!("[+] mounting the container image");

    std::fs::create_dir(CONTAINER_PATH)?;
    mount(
        Some("/dev/vda"),
        CONTAINER_PATH,
        Some("squashfs"),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )?;

    println!("[+] retrieving the challenge metadata");
    let challenge_metadata = match perform_query(
        &SocketAddr::V4(SocketAddrV4::new(gateway, server_port)),
        CirceQueryRaw::Challenge(ChallengeQuery {
            kind: ChallengeQueryKind::Client(ClientQuery::RetrieveChallengeMetadata),
            challenge_name: challenge_name.to_string(),
        }),
    )? {
        CirceResponseData::ChallengeMetadata(meta) => meta,
        _ => return Err(Error::InvalidServerResponse),
    };

    println!("[+] retrieving the container configuration");
    let mut docker_config = match perform_query(
        &SocketAddr::V4(SocketAddrV4::new(gateway, server_port)),
        CirceQueryRaw::Challenge(ChallengeQuery {
            kind: ChallengeQueryKind::Client(ClientQuery::RetrieveDockerConfig),
            challenge_name: challenge_name.to_string(),
        }),
    )? {
        CirceResponseData::DockerImageConfig(config) => config,
        _ => return Err(Error::InvalidServerResponse),
    };

    println!("[+] mounting a writable overlay on top of the container");

    let container_tmpfs = Path::new("/container_tmpfs").to_owned();
    std::fs::create_dir(&container_tmpfs)?;
    mount(
        Some("none"),
        &container_tmpfs,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    let mut container_upperdir = container_tmpfs.clone();
    container_upperdir.push("upperdir");
    std::fs::create_dir(&container_upperdir)?;
    let mut container_workdir = container_tmpfs.clone();
    container_workdir.push("workdir");
    std::fs::create_dir(&container_workdir)?;
    let mut container_merged = container_tmpfs.clone();
    container_merged.push("merged");
    std::fs::create_dir(&container_merged)?;
    mount(
        Some("overlay"),
        &container_merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(
            format!(
                "lowerdir={},upperdir={},workdir={}",
                CONTAINER_PATH,
                container_upperdir.to_string_lossy(),
                container_workdir.to_string_lossy()
            )
            .as_str(),
        ),
    )?;

    let container_pid = {
        // 8MB
        let mut container_stack = Vec::<u8>::with_capacity(8 * 1024 * 1024);
        container_stack.resize(8 * 1024 * 1024, 0u8);
        let challenge_name = challenge_name.clone();
        let pid = clone(
            Box::new(|| -> isize {
                container_process(
                    &container_merged,
                    &challenge_metadata,
                    &mut docker_config,
                    &challenge_name,
                )
                .expect("The process broke");
                0
            }),
            container_stack.as_mut_slice(),
            CloneFlags::CLONE_UNTRACED | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID,
            None,
        )?;
        pid
    };

    println!("[+] spawing a shell");

    let shell_process = unsafe { fork()? };
    if let ForkResult::Child = shell_process {
        setsid()?;
        // open the serial device and make it the controlling terminal
        setup_term(false)?;

        let sh_path = CStr::from_bytes_with_nul(b"/bin/sh\0").unwrap();
        execve(sh_path, &[sh_path], &[] as &[&CStr; 0])?;
    }

    let shell_child = match shell_process {
        ForkResult::Parent { child: shell_child } => shell_child,
        _ => panic!("Couldn't retrieve the PIDs of the forked processes"),
    };

    loop {
        sleep(1);

        // return if any of the two process groups died
        if let Err(e) = nix::sys::wait::waitpid(
            nix::unistd::Pid::from_raw(-container_pid.as_raw()),
            Some(WaitPidFlag::WNOHANG),
        ) {
            if e == nix::errno::Errno::ECHILD {
                break;
            }
            panic!("{:?}", e);
        }
        if let Err(e) = nix::sys::wait::waitpid(
            nix::unistd::Pid::from_raw(-shell_child.as_raw()),
            Some(WaitPidFlag::WNOHANG),
        ) {
            if e == nix::errno::Errno::ECHILD {
                break;
            }
            panic!("{:?}", e);
        }
    }

    send_message_to_manager(
        &challenge_name,
        gateway,
        server_port,
        InitramfsQuery::ShuttingDown,
    )?;

    unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    Ok(())
}
