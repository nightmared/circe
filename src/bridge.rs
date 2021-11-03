use ipnetwork::Ipv4Network;
use libc::{in_addr, sockaddr_in};
// Shamelessly taken from https://github.com/levex/network-bridge-rs. Please
// uphold the rightful copyright owners rights:
// Copyright 2018 Levente Kurusa <lkurusa@acm.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

extern crate libc;

use std::ffi::CString;

mod private {
    use nix::{ioctl_readwrite_bad, ioctl_write_ptr_bad};

    extern crate libc;
    /// The maximum length of an interface name.
    pub const IFNAMSIZ: usize = 16;
    pub const SIOCBRADDBR: u16 = 0x89a0;
    pub const SIOCBRDELBR: u16 = 0x89a1;
    pub const SIOCGIFINDEX: u16 = 0x8933;
    pub const SIOCBRADDIF: u16 = 0x89a2;
    pub const SIOCBRDELIF: u16 = 0x89a3;
    pub const SIOCGIFFLAGS: u16 = 0x8913;
    pub const SIOCSIFFLAGS: u16 = 0x8914;
    pub const SIOCSIFADDR: u16 = 0x8916;
    pub const SIOCSIFNETMASK: u16 = 0x891c;

    #[repr(C)]
    #[derive(Debug)]
    pub struct ifreq {
        pub ifrn_name: [libc::c_char; IFNAMSIZ],
        pub ifru_ivalue: u32,
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct ifreq_ipaddr {
        pub ifrn_name: [libc::c_char; IFNAMSIZ],
        pub ifru_ivalue: libc::sockaddr_in,
    }

    ioctl_write_ptr_bad!(ioctl_addbr, SIOCBRADDBR, libc::c_char);
    ioctl_write_ptr_bad!(ioctl_delbr, SIOCBRDELBR, libc::c_char);
    ioctl_write_ptr_bad!(ioctl_ifindex, SIOCGIFINDEX, ifreq);
    ioctl_write_ptr_bad!(ioctl_addif, SIOCBRADDIF, ifreq);
    ioctl_write_ptr_bad!(ioctl_delif, SIOCBRDELIF, ifreq);
    ioctl_readwrite_bad!(ioctl_getifflags, SIOCGIFFLAGS, ifreq);
    ioctl_write_ptr_bad!(ioctl_setifflags, SIOCSIFFLAGS, ifreq);
    ioctl_write_ptr_bad!(ioctl_setifaddr, SIOCSIFADDR, ifreq_ipaddr);
    ioctl_write_ptr_bad!(ioctl_setifnetmask, SIOCSIFNETMASK, ifreq_ipaddr);
}
pub use private::IFNAMSIZ;
use private::{
    ifreq, ifreq_ipaddr, ioctl_addbr, ioctl_addif, ioctl_delbr, ioctl_delif, ioctl_getifflags,
    ioctl_ifindex, ioctl_setifaddr, ioctl_setifflags, ioctl_setifnetmask,
};

/// Builder pattern for constructing networking bridges.
///
/// # Example
///
/// Create a bridge named `hello_world_br` and attach two interfaces: `eth0` and `eth1`.
///
/// ```rust,no_run
///# use ::network_bridge::BridgeBuilder;
///   let result = BridgeBuilder::new("hello_world_br")
///                 .interface("eth0")
///                 .interface("eth1")
///                 .build();
/// ```
pub struct BridgeBuilder {
    name: String,
    interfaces: Vec<i32>,
}

impl BridgeBuilder {
    /// Start building a new bridge, setting its interface name.
    pub fn new(name: &str) -> BridgeBuilder {
        BridgeBuilder {
            name: name.to_string(),
            interfaces: Vec::new(),
        }
    }

    /// Override the name of the bridge.
    pub fn name(self, name: &str) -> BridgeBuilder {
        BridgeBuilder {
            name: name.to_string(),
            interfaces: self.interfaces,
        }
    }

    /// Attach an interface to the bridge.
    pub fn interface(self, name: &str) -> Result<BridgeBuilder, nix::Error> {
        let idx = interface_id(name)?;
        Ok(BridgeBuilder {
            name: self.name,
            interfaces: {
                let mut ifs = self.interfaces;
                ifs.push(idx);
                ifs
            },
        })
    }

    /// Remove an interface from the bridge.
    pub fn remove_interface(self, name: &str) -> Result<BridgeBuilder, nix::Error> {
        let idx = interface_id(name)?;
        Ok(BridgeBuilder {
            name: self.name,
            interfaces: self.interfaces.into_iter().filter(|x| *x != idx).collect(),
        })
    }

    /// Finalize the builder, creating the bridge and attaching any interfaces.
    pub fn build(self) -> Result<(), nix::Error> {
        create_bridge(&self.name)?;
        for i in self.interfaces {
            add_interface_to_bridge(i, &self.name)?;
        }

        Ok(())
    }
}

/// Create a network bridge using the interface name supplied.
pub fn create_bridge(name: &str) -> Result<i32, nix::Error> {
    /* Open a socket */
    let res = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    /* use the SIOCBRADDRBR ioctl to add the bridge */
    let cstr = CString::new(name).unwrap();
    unsafe { ioctl_addbr(res, cstr.as_ptr()) }
}

/// Delete an existing network bridge of the interface name supplied.
pub fn delete_bridge(name: &str) -> Result<i32, nix::Error> {
    /* Open a socket */
    let res = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    /* use the SIOCBRDELBR ioctl to delete the bridge */
    let cstr = CString::new(name).unwrap();
    unsafe { ioctl_delbr(res, cstr.as_ptr()) }
}

/// Converts an interface name into the identifier used by the kernel.
///
/// This can also be retrieved via sysfs, if mounted to /sys:
///
/// ```shell
/// $ cat /sys/class/net/eth0/ifindex
/// 1
/// ```
pub fn interface_id(interface: &str) -> Result<i32, nix::Error> {
    /* do some validation */
    if interface.len() == 0 || interface.len() >= IFNAMSIZ {
        return Err(nix::Error::from(nix::errno::Errno::EINVAL));
    }
    let length = interface.len();

    /* Open a socket */
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    let cstr = CString::new(interface).unwrap();

    /* create the ifreq structure */
    let mut ifr = ifreq {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: 0,
    };

    let result = unsafe {
        /*
         * This is safe because length is guaranteed to be less than IFNAMSIZ,
         * and the two variables can never overlap
         */
        std::ptr::copy_nonoverlapping(cstr.as_ptr(), ifr.ifrn_name.as_mut_ptr(), length);
        /*
         * SIOCGIFINDEX doesn't care about the rest of the fields, so this
         * should be safe
         */
        ioctl_ifindex(sock, &ifr)
    };

    result.map(|_| ifr.ifru_ivalue as i32)
}

fn bridge_del_add_if(interface_id: i32, bridge: &str, add: bool) -> Result<i32, nix::Error> {
    /* validate bridge name */
    if bridge.len() == 0 || bridge.len() >= IFNAMSIZ {
        return Err(nix::Error::from(nix::errno::Errno::EINVAL));
    }
    let length = bridge.len();

    /* Open a socket */
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    let mut ifr = ifreq {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: interface_id as u32,
    };

    let br_cstr = CString::new(bridge).unwrap();

    unsafe {
        /* copy the bridge name to the ifreq */
        std::ptr::copy_nonoverlapping(br_cstr.as_ptr(), ifr.ifrn_name.as_mut_ptr(), length);

        if add {
            ioctl_addif(sock, &ifr)
        } else {
            ioctl_delif(sock, &ifr)
        }
    }
}

/// Attach an interface to a bridge.
///
/// The bridge must already exist.
pub fn add_interface_to_bridge(interface_id: i32, bridge: &str) -> Result<i32, nix::Error> {
    bridge_del_add_if(interface_id, bridge, true)
}

/// Remove an interface from a bridge.
///
/// The bridge must already exist and the interface must already be attached to the bridge.
pub fn delete_interface_from_bridge(interface_id: i32, bridge: &str) -> Result<i32, nix::Error> {
    bridge_del_add_if(interface_id, bridge, false)
}

pub fn interface_get_flags(interface_name: &str) -> Result<u32, nix::Error> {
    /* validate the interface name */
    if interface_name.len() == 0 || interface_name.len() >= IFNAMSIZ {
        return Err(nix::Error::from(nix::errno::Errno::EINVAL));
    }
    let length = interface_name.len();

    /* Open a socket */
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    let mut ifr = ifreq {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: 0,
    };

    let if_cstr = CString::new(interface_name).unwrap();

    unsafe {
        /* copy the bridge name to the ifreq */
        std::ptr::copy_nonoverlapping(if_cstr.as_ptr(), ifr.ifrn_name.as_mut_ptr(), length);

        ioctl_getifflags(sock, &mut ifr as *mut ifreq)?;
        Ok(ifr.ifru_ivalue)
    }
}

pub fn interface_set_flags(interface_name: &str, flags: u32) -> Result<(), nix::Error> {
    /* validate the interface name */
    if interface_name.len() == 0 || interface_name.len() >= IFNAMSIZ {
        return Err(nix::Error::from(nix::errno::Errno::EINVAL));
    }
    let length = interface_name.len();

    /* Open a socket */
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    let mut ifr = ifreq {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: flags,
    };

    let if_cstr = CString::new(interface_name).unwrap();

    unsafe {
        /* copy the bridge name to the ifreq */
        std::ptr::copy_nonoverlapping(if_cstr.as_ptr(), ifr.ifrn_name.as_mut_ptr(), length);

        ioctl_setifflags(sock, &mut ifr as *mut ifreq)?;
    }

    Ok(())
}

pub fn interface_set_ip(interface_name: &str, net: Ipv4Network) -> Result<(), nix::Error> {
    /* validate the interface name */
    if interface_name.len() == 0 || interface_name.len() >= IFNAMSIZ {
        return Err(nix::Error::from(nix::errno::Errno::EINVAL));
    }
    let length = interface_name.len();

    /* Open a socket */
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    let if_cstr = CString::new(interface_name).unwrap();

    let ip = sockaddr_in {
        sin_family: AddressFamily::Inet as u16,
        sin_addr: in_addr {
            s_addr: u32::from(net.ip()).to_be(),
        },
        sin_port: 0,
        sin_zero: [0; 8],
    };

    let mut ifr_ip = ifreq_ipaddr {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: ip,
    };

    let mask = sockaddr_in {
        sin_family: AddressFamily::Inet as u16,
        sin_addr: in_addr {
            s_addr: u32::from(net.mask()).to_be(),
        },
        sin_port: 0,
        sin_zero: [0; 8],
    };

    let mut ifr_mask = ifreq_ipaddr {
        ifrn_name: [0; IFNAMSIZ],
        ifru_ivalue: mask,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(if_cstr.as_ptr(), ifr_ip.ifrn_name.as_mut_ptr(), length);
        ioctl_setifaddr(sock, &mut ifr_ip as *mut ifreq_ipaddr)?;

        std::ptr::copy_nonoverlapping(if_cstr.as_ptr(), ifr_mask.ifrn_name.as_mut_ptr(), length);
        ioctl_setifnetmask(sock, &mut ifr_mask as *mut ifreq_ipaddr)?;
    }

    Ok(())
}
