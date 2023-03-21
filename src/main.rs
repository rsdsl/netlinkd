use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_ip_config::IpConfig;

fn main() -> Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

    link::up("eth0".into())?;
    link::up("eth1".into())?;

    match configure_eth0() {
        Ok(_) => println!("[netlinkd] configure eth0 statically (10.128.0.254/24)"),
        Err(e) => {
            println!("[netlinkd] can't configure eth0: {:?}", e);
            return Err(e);
        }
    }

    let ip_config = Path::new(rsdsl_ip_config::LOCATION);
    while !ip_config.exists() {
        println!("[netlinkd] waiting for PPPoE connection");
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
        Err(e) => println!("[netlinkd] watch error: {:?}", e),
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

fn configure_wan() {
    match configure_rsppp0() {
        Ok(_) => println!("[netlinkd] configure rsppp0 with PPPoE data"),
        Err(e) => println!("[netlinkd] can't configure rsppp0: {:?}", e),
    }
}

fn configure_rsppp0() -> Result<()> {
    link::up("rsppp0".into())?;

    let mut file = File::open(rsdsl_ip_config::LOCATION)?;
    let ip_config: IpConfig = serde_json::from_reader(&mut file)?;

    addr::flush("rsppp0".into())?;
    addr::add("rsppp0".into(), IpAddr::V4(ip_config.addr), 32)?;

    route::add4(ip_config.rtr, 32, None, "rsppp0".into())?;
    route::add4(
        Ipv4Addr::UNSPECIFIED,
        0,
        Some(ip_config.rtr),
        "rsppp0".into(),
    )?;

    Ok(())
}
