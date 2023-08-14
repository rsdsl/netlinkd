use rsdsl_netlinkd::error::{Error, Result};
use rsdsl_netlinkd::{addr, link, route};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;

const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

fn main() -> Result<()> {
    println!("wait for eth0");
    link::wait_exists("eth0".into())?;
    println!("detect eth0");

    link::up("eth0".into())?;

    match configure_eth0() {
        Ok(_) => println!("configure eth0 statically (10.128.0.254/24, fe80::1/64)"),
        Err(e) => {
            println!("can't configure eth0: {}", e);
            return Err(e);
        }
    }

    match setup_vlans("eth0") {
        Ok(_) => println!("setup vlans"),
        Err(e) => {
            println!("can't setup vlans: {}", e);
            return Err(e);
        }
    }

    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    println!("enable ipv4 routing");

    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    println!("enable ipv6 routing");

    println!("wait for eth1");
    link::wait_exists("eth1".into())?;
    println!("detect eth1");

    link::up("eth1".into())?;

    match enable_modem_access() {
        Ok(_) => println!("configure eth1 modem (192.168.1.2/24)"),
        Err(e) => {
            println!("can't configure eth1 modem: {}", e);
            return Err(e);
        }
    }

    let ip_config = Path::new(rsdsl_ip_config::LOCATION);
    while !ip_config.exists() {
        println!("wait for pppoe");
        thread::sleep(Duration::from_secs(8));
    }

    configure_wan();

    let mut watcher = notify::recommended_watcher(|res: notify::Result<Event>| match res {
        Ok(event) => match event.kind {
            EventKind::Create(kind) if kind == CreateKind::File => {
                configure_wan();
            }
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                configure_wan();
            }
            _ => {}
        },
        Err(e) => println!("watch error: {:?}", e),
    })?;

    watcher.watch(ip_config, RecursiveMode::NonRecursive)?;

    let pd_config = Path::new(rsdsl_pd_config::LOCATION);

    println!("wait for dhcp6");
    while !pd_config.exists() {
        thread::sleep(Duration::from_secs(8));
    }

    configure_ipv6();

    let mut watcher = notify::recommended_watcher(|res: notify::Result<Event>| match res {
        Ok(event) => match event.kind {
            EventKind::Create(kind) if kind == CreateKind::File => {
                configure_ipv6();
            }
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                configure_ipv6();
            }
            _ => {}
        },
        Err(e) => println!("watch error: {:?}", e),
    })?;

    watcher.watch(pd_config, RecursiveMode::NonRecursive)?;

    loop {
        thread::sleep(Duration::MAX)
    }
}

fn configure_eth0() -> Result<()> {
    addr::flush("eth0".into())?;
    addr::add_link_local("eth0".into(), LINK_LOCAL.into(), 64)?;
    addr::add("eth0".into(), "10.128.0.254".parse()?, 24)?;

    Ok(())
}

fn setup_vlans(base: &str) -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, zone) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("{}.{}", base, vlan_id);
        let vlan_addr = IpAddr::V4(Ipv4Addr::new(10, 128, vlan_id as u8, 254));

        link::add_vlan(vlan_name.clone(), base.to_owned(), vlan_id as u16)?;

        addr::add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
        addr::add(vlan_name.clone(), vlan_addr, 24)?;

        link::up(vlan_name.clone())?;

        println!(
            "configure {} ({}/24, fe80::1/64) zone {}",
            vlan_name, vlan_addr, zone
        );
    }

    Ok(())
}

fn enable_modem_access() -> Result<()> {
    addr::flush("eth1".into())?;
    addr::add("eth1".into(), "192.168.1.2".parse()?, 24)?;

    Ok(())
}

fn configure_wan() {
    match configure_ppp0() {
        Ok(_) => println!("configure ppp0 with pppoe data"),
        Err(e) => println!("can't configure ppp0: {:?}", e),
    }
}

fn configure_ppp0() -> Result<()> {
    link::set_mtu("ppp0".into(), 1492)?;
    link::up("ppp0".into())?;

    let mut file = File::open(rsdsl_ip_config::LOCATION)?;
    let ip_config: DsConfig = serde_json::from_reader(&mut file)?;

    addr::flush("ppp0".into())?;
    route::flush("ppp0".into())?;

    if let Some(v4) = ip_config.v4 {
        addr::add("ppp0".into(), IpAddr::V4(v4.addr), 32)?;
        route::add4(Ipv4Addr::UNSPECIFIED, 0, None, "ppp0".into())?;
    }

    if let Some(v6) = ip_config.v6 {
        addr::add("ppp0".into(), IpAddr::V6(v6.laddr), 64)?;
        route::add6(Ipv6Addr::UNSPECIFIED, 0, None, "ppp0".into())?;
    }

    Ok(())
}

fn configure_ipv6() {
    match configure_all_v6() {
        Ok(_) => println!("configure ipv6"),
        Err(e) => println!("can't configure ipv6: {:?}", e),
    }
}

fn configure_all_v6() -> Result<()> {
    let mut file = File::open(rsdsl_pd_config::LOCATION)?;
    let pdconfig: PdConfig = serde_json::from_reader(&mut file)?;

    let prefix = Ipv6Net::new(pdconfig.prefix, pdconfig.len)?.trunc();
    let mut subnets = prefix.subnets(64)?;

    addr::flush6_global()?;
    addr::add("ppp0".into(), IpAddr::V6(next_ifid1(&mut subnets)?), 64)?;

    let addr = next_ifid1(&mut subnets)?;

    fs::write("/proc/sys/net/ipv6/conf/eth0/accept_ra", "0")?;

    addr::flush6("eth0".into())?;
    addr::add("eth0".into(), addr.into(), 64)?;

    println!("configure eth0 ({}/64)", addr);

    let zones = ["trusted", "untrusted", "isolated", "exposed"];
    for (i, zone) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);
        let vlan_addr = next_ifid1(&mut subnets)?;

        fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/accept_ra", vlan_name),
            "0",
        )?;

        addr::flush6(vlan_name.clone())?;
        addr::add(vlan_name.clone(), vlan_addr.into(), 64)?;

        println!("configure {} ({}/64) zone {}", vlan_name, vlan_addr, zone);
    }

    Ok(())
}

fn next_ifid1<T: Iterator<Item = Ipv6Net>>(subnets: &mut T) -> Result<Ipv6Addr> {
    Ok((u128::from(subnets.next().ok_or(Error::NotEnoughIpv6Subnets)?.addr()) + 1).into())
}
