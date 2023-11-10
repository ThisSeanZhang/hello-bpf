use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration, thread::sleep};

use anyhow::{Ok, bail};
use anyhow::Result;


mod bpf_thread {
    include!(concat!(env!("OUT_DIR"), "/thread.skel.rs"));
}

use bpf_thread::*;
use libbpf_rs::{skel::{SkelBuilder, OpenSkel}, UprobeOpts};
use nix::libc;

mod profile;
mod offcpu;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}


fn main() -> Result<()> {
    bump_memlock_rlimit()?;
    crate::offcpu::start()?;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;


    let mut thread_builder = ThreadSkelBuilder::default();
    thread_builder.obj_builder.debug(true);
    let thread_open = thread_builder.open()?;

    let mut tread_skel = thread_open.load()?;

    let _ = tread_skel.progs_mut().xdp_pass().attach_xdp(3);
    let a = tread_skel.progs_mut().tcp_v4_connect_enter().attach_kprobe(false, "tcp_v4_connect");
    let a = tread_skel.progs_mut().catch_ssl_write()
    .attach_uprobe_with_opts(-1,  "/usr/lib/libssl.so.3", 0, UprobeOpts {
        retprobe: false,
        func_name: "SSL_write".to_string(),
        ..Default::default()
    });

    println!("Hello, world!");

    // Block until SIGINT
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    Ok(())
}
