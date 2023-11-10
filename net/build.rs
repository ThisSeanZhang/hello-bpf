use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/netpack.bpf.c";
const SRC2: &str = "src/bpf/socketfilter.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    let netpack = out.clone().join("netpack.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&netpack)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    let socketfilter = out.clone().join("socketfilter.skel.rs");
    SkeletonBuilder::new()
        .source(SRC2)
        .build_and_generate(&socketfilter)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC2}");
}
