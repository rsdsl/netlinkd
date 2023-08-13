use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_ip_config::DsConfig;

fn main() -> Result<()> {
    println!("wait for eth0");
    link::wait_exists("eth0".into())?;
    println!("detect eth0");

    link::up("eth0".into())?;

    match configure_eth0() {
        Ok(_) => println!("configure eth0 statically (10.128.0.254/24)"),
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

    loop {
        thread::sleep(Duration::MAX)
    }
}

fn configure_eth0() -> Result<()> {
    addr::flush("eth0".into())?;
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
        addr::add(vlan_name.clone(), vlan_addr, 24)?;
        link::up(vlan_name.clone())?;

        println!("configure {} ({}/24) zone {}", vlan_name, vlan_addr, zone);
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
