#![feature(path_file_prefix)]

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/thread.bpf.c";
const P_SRC: &str = "./src/bpf/profile.bpf.c";
const OFF_SRC: &str = "./src/bpf/offcputime.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("thread.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args("-Wno-compare-distinct-pointer-types")
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");

    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("profile.skel.rs");
    SkeletonBuilder::new()
        .source(P_SRC)
        .build_and_generate(&out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", P_SRC);

    let mut out =
    PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("offcputime.skel.rs");
    SkeletonBuilder::new()
        .source(OFF_SRC)
        .build_and_generate(&out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", P_SRC);
}
