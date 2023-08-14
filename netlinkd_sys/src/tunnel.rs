use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{internal, Error, Result};

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
        let tnlname = CString::new(name)?.into_raw();
        let ifmaster = CString::new(master)?.into_raw();

        let err = unsafe {
            internal::netlinkd_create_6in4(
                tnlname,
                ifmaster,
                u32::from(laddr).to_be(),
                u32::from(raddr).to_be(),
            )
        };

        let _ = unsafe { CString::from_raw(tnlname) };
        let _ = unsafe { CString::from_raw(ifmaster) };

        if err < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(Self {
                name: name.to_owned(),
            })
        }
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
        let tnlname = CString::new(name)?.into_raw();
        let ifmaster = CString::new(master)?.into_raw();

        let mut loctets = laddr.octets();

        // Swap last 32 bits to the front.
        loctets.swap(0, 12);
        loctets.swap(1, 13);
        loctets.swap(2, 14);
        loctets.swap(3, 15);

        // Swap second 32 bit segment to the right by 32 bits.
        loctets.swap(4, 8);
        loctets.swap(5, 9);
        loctets.swap(6, 10);
        loctets.swap(7, 11);

        // Swap second 32 bit segment to the back (by 64 bits).
        loctets.swap(4, 12);
        loctets.swap(5, 13);
        loctets.swap(6, 14);
        loctets.swap(7, 15);

        let err = unsafe {
            internal::netlinkd_create_4in6(
                tnlname,
                ifmaster,
                &loctets as *const u8,
                &raddr.octets() as *const u8,
            )
        };

        let _ = unsafe { CString::from_raw(tnlname) };
        let _ = unsafe { CString::from_raw(ifmaster) };

        if err < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(Self {
                name: name.to_owned(),
            })
        }
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
