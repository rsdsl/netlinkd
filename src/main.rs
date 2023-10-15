use rsdsl_netlinkd::{addr, link, route};
use rsdsl_netlinkd::{Error, Result};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use sysinfo::{ProcessExt, Signal, System, SystemExt};

const ADDR_AFTR: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 1);
const ADDR_B4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 2);
const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

fn main() -> Result<()> {
    println!("[info] wait for eth0");
    link::wait_exists("eth0".into())?;
    println!("[info] detect eth0");

    link::up("eth0".into())?;

    configure_lan()?;
    println!("[info] config eth0 10.128.0.254/24 fe80::1/64");

    create_vlans()?;
    configure_vlans()?;
    println!("[info] config vlans 10.128.0.0/16 fe80::1/64");

    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    println!("[info] enable ipv4 routing");

    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    fs::write("/proc/sys/net/ipv6/conf/default/forwarding", "1")?;
    println!("[info] enable ipv6 routing");

    println!("[info] wait for eth1");
    link::wait_exists("eth1".into())?;
    println!("[info] detect eth1");

    link::up("eth1".into())?;

    configure_modem()?;
    println!("[info] config eth1 192.168.1.2/24 (modem)");

    let mut signals = Signals::new([SIGUSR1])?;
    for _ in signals.forever() {
        configure_wan_logged();
    }

    Ok(()) // unreachable
}

fn configure_lan() -> Result<()> {
    addr::flush("eth0".into())?;
    addr::add_link_local("eth0".into(), LINK_LOCAL.into(), 64)?;
    addr::add("eth0".into(), "10.128.0.254".parse()?, 24)?;

    Ok(())
}

fn create_vlans() -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, _) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);

        link::add_vlan(vlan_name.clone(), "eth0".to_string(), vlan_id as u16)?;
        link::up(vlan_name.clone())?;

        addr::flush(vlan_name.clone())?;
    }

    Ok(())
}

fn configure_vlans() -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, _) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);
        let vlan_addr = IpAddr::V4(Ipv4Addr::new(10, 128, vlan_id as u8, 254));

        addr::add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
        addr::add(vlan_name.clone(), vlan_addr, 24)?;
    }

    Ok(())
}

fn configure_modem() -> Result<()> {
    addr::flush("eth1".into())?;
    addr::add("eth1".into(), "192.168.1.2".parse()?, 24)?;

    Ok(())
}

fn configure_wan_logged() {
    match configure_wan() {
        Ok(_) => {}
        Err(e) => println!("[warn] config wan: {}", e),
    }
}

fn configure_wan() -> Result<()> {
    if let Some(ds_config) = read_ds_config_optional() {
        link::set_mtu("ppp0".to_string(), 1492)?;
        link::up("ppp0".to_string())?;

        // Deconfigure everything, just to be safe.
        addr::flush("ppp0".to_string())?;
        route::flush("ppp0".to_string())?;

        if let Some(v4) = ds_config.v4 {
            addr::add("ppp0".to_string(), v4.addr.into(), 32)?;
            route::add4(Ipv4Addr::UNSPECIFIED, 0, None, "ppp0".to_string())?;

            println!("[info] config ppp0 {}/32", v4.addr);
        }

        if let Some(v6) = ds_config.v6 {
            addr::add_link_local("ppp0".to_string(), v6.laddr.into(), 64)?;
            route::add6(Ipv6Addr::UNSPECIFIED, 0, None, "ppp0".to_string())?;

            println!("[info] config ppp0 ll {}/64", v6.laddr);

            if let Some(pd_config) = read_pd_config_optional() {
                let prefix = Ipv6Net::new(pd_config.prefix, pd_config.len)?.trunc();
                let mut subnets = prefix.subnets(64)?;

                let addr_wan = next_ifid1(&mut subnets)?;

                addr::add("ppp0".to_string(), addr_wan.into(), 64)?;
                println!("[info] config ppp0 gua {}/64", addr_wan);

                let addr_lan = next_ifid1(&mut subnets)?;

                addr::flush6("eth0".to_string())?;
                addr::add_link_local("eth0".to_string(), LINK_LOCAL.into(), 64)?;
                addr::add("eth0".to_string(), addr_lan.into(), 64)?;

                println!("[info] config eth0 gua {}/64", addr_lan);

                let zones = ["trusted", "untrusted", "isolated", "exposed"];
                for (i, zone) in zones.iter().enumerate() {
                    let vlan_id = 10 * (i + 1);
                    let vlan_name = format!("eth0.{}", vlan_id);
                    let vlan_addr = next_ifid1(&mut subnets)?;

                    addr::flush6(vlan_name.clone())?;
                    addr::add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
                    addr::add(vlan_name.clone(), vlan_addr.into(), 64)?;

                    println!(
                        "[info] config {} gua {}/64 zone {}",
                        vlan_name, vlan_addr, zone
                    );
                }

                for radvd in System::default().processes_by_exact_name("/bin/rsdsl_radvd") {
                    radvd.kill_with(Signal::User1);
                }

                if link::exists("dslite0".to_string())? {
                    link::up("dslite0".to_string())?;

                    addr::flush("dslite0".to_string())?;
                    addr::add("dslite0".to_string(), ADDR_B4.into(), 29)?;

                    if ds_config.v4.is_none() {
                        route::add4(
                            Ipv4Addr::UNSPECIFIED,
                            0,
                            Some(ADDR_AFTR),
                            "dslite0".to_string(),
                        )?;
                    }

                    println!("[info] config dslite0 {}/29", ADDR_B4);
                }
            }
        }
    }

    Ok(())
}

fn read_ds_config_optional() -> Option<DsConfig> {
    let mut file = File::open(rsdsl_ip_config::LOCATION).ok()?;
    serde_json::from_reader(&mut file).ok()
}

fn read_pd_config_optional() -> Option<PdConfig> {
    let mut file = File::open(rsdsl_pd_config::LOCATION).ok()?;
    serde_json::from_reader(&mut file).ok()
}

fn next_ifid1<T: Iterator<Item = Ipv6Net>>(subnets: &mut T) -> Result<Ipv6Addr> {
    Ok((u128::from(subnets.next().ok_or(Error::NotEnoughIpv6Subnets)?.addr()) + 1).into())
}
