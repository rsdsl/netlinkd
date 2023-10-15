use crate::{Error, Result};

use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield::bitfield;

const SIOCADDTUNNEL: u64 = 0x89F0 + 1;

/// A handle to a 6in4 tunnel. The interface is automatically deleted on drop.
#[derive(Debug)]
pub struct Sit {
    name: String,
}

impl Drop for Sit {
    fn drop(&mut self) {
        let _ = self.do_delete();
    }
}

impl Sit {
    pub fn new(name: &str, master: &str, laddr: Ipv4Addr, raddr: Ipv4Addr) -> Result<Self> {
        let mut vihl = VerIhl::default();

        vihl.set_version(4);
        vihl.set_ihl(5);

        let p = IpTunnelParm4 {
            name: CString::new(name)?,
            link: libc::if_nametoindex(CString::new(master)?.as_ptr()),
            i_flags: 0,
            o_flags: 0,
            i_key: 0,
            o_key: 0,
            iph: IpHdr4 {
                vihl,
                tos: 0,
                tot_len: 0,
                id: 0,
                frag_off: 0,
                check: 0,
                ttl: 64,
                protocol: libc::IPPROTO_IPV6 as u8,
                saddr: laddr,
                daddr: raddr,
            },
        };

        if p.link == 0 {
            return Err(Error::LinkNotFound(master.to_owned()));
        }

        let ifr = IfReq4 {
            name: CString::new("sit0")?,
            ifru_data: &p,
        };

        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if libc::ioctl(fd, SIOCADDTUNNEL, &ifr) < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Errors are safe to ignore because they don't affect tunnel creation
        // but do leave the program in an inconsistent state.
        libc::close(fd);

        Ok(Self {
            name: name.to_owned(),
        })
    }

    fn do_delete(&self) -> Result<()> {
        let tnlname = CString::new(self.name.as_str())?.into_raw();
        let err = unsafe { internal::netlinkd_delete_tunnel(tnlname) };
        let _ = unsafe { CString::from_raw(tnlname) };

        if err < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

/// A handle to a 4in6 tunnel. The interface is automatically deleted on drop.
#[derive(Debug)]
pub struct IpIp6 {
    name: String,
}

impl Drop for IpIp6 {
    fn drop(&mut self) {
        let _ = self.do_delete();
    }
}

impl IpIp6 {
    pub fn new(name: &str, master: &str, laddr: Ipv6Addr, raddr: Ipv6Addr) -> Result<Self> {
        let p = IpTunnelParm6 {
            name: CString::new(name)?,
            link: libc::if_nametoindex(CString::new(master)?.as_ptr()),
            i_flags: 0,
            o_flags: 0,
            i_key: 0,
            o_key: 0,
            iph: IpHdr6 {
                saddr: laddr,
                daddr: raddr,
            },
        };

        if p.link == 0 {
            return Err(Error::LinkNotFound(master.to_owned()));
        }

        let ifr = IfReq6 {
            name: CString::new("ip6tnl0")?,
            ifru_data: &p,
        };

        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_IP);
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if libc::ioctl(fd, SIOCADDTUNNEL, &ifr) < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Errors are safe to ignore because they don't affect tunnel creation
        // but do leave the program in an inconsistent state.
        libc::close(fd);

        Ok(Self {
            name: name.to_owned(),
        })
    }

    fn do_delete(&self) -> Result<()> {
        let tnlname = CString::new(self.name.as_str())?.into_raw();
        let err = unsafe { internal::netlinkd_delete_tunnel(tnlname) };
        let _ = unsafe { CString::from_raw(tnlname) };

        if err < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

bitfield! {
    #[derive(Default)]
    struct VerIhl(u8);
    impl Debug;

    version, set_version: 7, 4;
    ihl, set_ihl: 3, 0;
}

#[derive(Debug)]
#[repr(C)]
struct IpHdr4 {
    vihl: VerIhl,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
}

#[derive(Debug)]
#[repr(C)]
struct IpTunnelParm4 {
    name: CString,
    link: u32,
    i_flags: u16,
    o_flags: u16,
    i_key: u32,
    o_key: u32,
    iph: IpHdr4,
}

#[derive(Debug)]
#[repr(C)]
struct IfReq4 {
    name: CString,
    ifru_data: *const IpTunnelParm4,
}

#[derive(Debug)]
#[repr(C)]
struct IpHdr6 {
    saddr: Ipv6Addr,
    daddr: Ipv6Addr,
}

#[derive(Debug)]
#[repr(C)]
struct IpTunnelParm6 {
    name: CString,
    link: u32,
    i_flags: u16,
    o_flags: u16,
    i_key: u32,
    o_key: u32,
    iph: IpHdr6,
}

#[derive(Debug)]
#[repr(C)]
struct IfReq6 {
    name: CString,
    ifru_data: *const IpTunnelParm6,
}
