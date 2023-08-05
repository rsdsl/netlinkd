mod error;
pub use error::*;

mod tunnel;
pub use tunnel::*;

mod internal {
    include!(concat!(env!("OUT_DIR"), "/netlinkd_bindings.rs"));
}
