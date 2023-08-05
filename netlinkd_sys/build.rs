use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=netlinkd/netlinkd.c");

    cc::Build::new()
        .file("netlinkd/netlinkd.c")
        .compile("netlinkd");

    let header = "netlinkd";
    let bindings = bindgen::Builder::default()
        .header(format!("netlinkd/{}.h", header))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join(format!("{}_bindings.rs", header)))
        .expect("Couldn't write bindings");
}
