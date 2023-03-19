use netlinkd::error::Result;
use netlinkd::link;

fn main() -> Result<()> {
    link::up("eth0".into())?;

    Ok(())
}
