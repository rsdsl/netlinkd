use crate::{Error, Result};

use std::ffi::{c_char, c_int, CString};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield::bitfield;

const SIOCADDTUNNEL: c_int = 0x89F0 + 1;
const SIOCDELTUNNEL: c_int = 0x89F0 + 2;

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
    pub fn new(name: String, master: String, laddr: Ipv4Addr, raddr: Ipv4Addr) -> Result<Self> {
        let mut vihl = VerIhl::default();

        vihl.set_version(4);
        vihl.set_ihl(5);

        let p = IpTunnelParm4 {
            name: CString::new(&*name)?.as_ptr(),
            link: unsafe { libc::if_nametoindex(CString::new(&*master)?.as_ptr()) },
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
            return Err(Error::LinkNotFound(master));
        }

        let ifr = IfReq4 {
            name: CString::new("sit0")?.as_ptr(),
            ifru_data: &p,
        };

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if unsafe { libc::ioctl(fd, SIOCADDTUNNEL, &ifr) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Errors are safe to ignore because they don't affect tunnel creation
        // but do leave the program in an inconsistent state.
        unsafe {
            libc::close(fd);
        }

        Ok(Self { name })
    }

    fn do_delete(&self) -> Result<()> {
        delete_tunnel(&self.name)
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
    pub fn new(name: String, master: String, laddr: Ipv6Addr, raddr: Ipv6Addr) -> Result<Self> {
        let p = IpTunnelParm6 {
            name: CString::new(&*name)?.as_ptr(),
            link: unsafe { libc::if_nametoindex(CString::new(&*master)?.as_ptr()) },
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
            return Err(Error::LinkNotFound(master));
        }

        let ifr = IfReq6 {
            name: CString::new("ip6tnl0")?.as_ptr(),
            ifru_data: &p,
        };

        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_IP) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if unsafe { libc::ioctl(fd, SIOCADDTUNNEL, &ifr) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Errors are safe to ignore because they don't affect tunnel creation
        // but do leave the program in an inconsistent state.
        unsafe {
            libc::close(fd);
        }

        Ok(Self { name })
    }

    fn do_delete(&self) -> Result<()> {
        delete_tunnel(&self.name)
    }
}

fn delete_tunnel(name: &str) -> Result<()> {
    let p = IpTunnelParm4 {
        name: CString::new(name)?.as_ptr(),
        link: 0,
        i_flags: 0,
        o_flags: 0,
        i_key: 0,
        o_key: 0,
        iph: IpHdr4 {
            vihl: VerIhl::default(),
            tos: 0,
            tot_len: 0,
            id: 0,
            frag_off: 0,
            ttl: 0,
            protocol: 0,
            check: 0,
            saddr: Ipv4Addr::UNSPECIFIED,
            daddr: Ipv4Addr::UNSPECIFIED,
        },
    };

    let ifr = IfReq4 {
        name: CString::new(name)?.as_ptr(),
        ifru_data: &p,
    };

    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_IP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    if unsafe { libc::ioctl(fd, SIOCDELTUNNEL, &ifr) } < 0 {
        return Err(io::Error::last_os_error().into());
    }

    // Errors are safe to ignore because they don't affect tunnel creation
    // but do leave the program in an inconsistent state.
    unsafe {
        libc::close(fd);
    }

    Ok(())
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
    name: *const c_char,
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
    name: *const c_char,
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
    name: *const c_char,
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
    name: *const c_char,
    ifru_data: *const IpTunnelParm6,
}
