use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::link;

fn main() -> Result<()> {
    link::up("eth0".into())?;
    link::up("eth1".into())?;

    Ok(())
}
