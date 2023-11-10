use anyhow::Ok;
use anyhow::bail;
use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::ProgramAttachType;
use libbpf_rs::TcHookBuilder;
use libc::c_int;
use libc::c_void;
use libc::sock_filter;
use libc::socklen_t;
use nix::sys::socket::setsockopt;
use plain::Plain;

use std::env;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::mem::size_of_val;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::Duration;


mod netpack {
    include!(concat!(env!("OUT_DIR"), "/netpack.skel.rs"));
}

mod socketfilter {
    include!(concat!(env!("OUT_DIR"), "/socketfilter.skel.rs"));
}

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// #ifndef __RUNQSLOWER_H
// #define __RUNQSLOWER_H

// #define TASK_COMM_LEN 16

// struct event {
// 	u8 task[TASK_COMM_LEN];
// 	__u64 delta_us;
// 	pid_t pid;
// };

// #endif /* __RUNQSLOWER_H */

// bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
//     &event, sizeof(event));

use netpack::*;

unsafe impl Plain for netpack_bss_types::so_event {}
unsafe impl Plain for socketfilter::socketfilter_bss_types::so_event {}

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

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = socketfilter::socketfilter_bss_types::so_event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    println!("{:?}", event);
    // let now = if let Ok(now) = OffsetDateTime::now_local() {
    //     let format = format_description!("[hour]:[minute]:[second]");
    //     now.format(&format)
    //         .unwrap_or_else(|_| "00:00:00".to_string())
    // } else {
    //     "00:00:00".to_string()
    // };

    // let task = std::str::from_utf8(&event.task).unwrap();

    // println!(
    //     "{:8} {:16} {:<7} {:<14}",
    //     now,
    //     task.trim_end_matches(char::from(0)),
    //     event.pid,
    //     event.delta_us
    // );
}
fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}


// #[cfg(target_os = "linux")]
// sockopt_impl!(
//     /// Set the mark for each packet sent through this socket (similar to the
//     /// netfilter MARK target but socket-based).
//     AttachBpf,
//     Both,
//     libc::SOL_SOCKET,
//     libc::SO_ATTACH_BPF,
//     i32
// );

const SOL_SOCKET: c_int = 1;
const SO_ATTACH_BPF:  c_int = 50;

use libc::{socket, AF_PACKET, SOCK_RAW, SOCK_NONBLOCK, SOCK_CLOEXEC};

use crate::socketfilter::SocketfilterMaps;
const ETH_P_ALL: u16 = 0x0003; // from if_ether.h for SOCK_RAW
/// Open a raw AF_PACKET socket for all protocols.
fn open_fd() -> Result<i32> {
    unsafe {
        match socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, ETH_P_ALL.to_be() as i32) {
            -1 => Err(Error::last_os_error().into()),
            fd => Ok(fd)
        }
    }
}

fn get_cgroup_fd(cgroup_path: &str) -> Result<i32> {

    let mut fd_file = File::open(cgroup_path)?;
    Ok(fd_file.as_raw_fd())

}

fn main() -> Result<()> {
    // let ifidx = nix::net::if_::if_nametoindex("ens160")? as i32;
    // let cgroup_fd = get_cgroup_fd("/sys/fs/cgroup")?;
    // println!("{cgroup_fd:?}");
    let is_cgroup2_unified_mode = cgroups_rs::hierarchies::is_cgroup2_unified_mode();
    
    // let a = cgroups_rs::Cgroup::load(cgroups_rs::hierarchies::auto(), cgroups_rs::cgroup::UNIFIED_MOUNTPOINT);
    // a
    // println!("{a:?}");
    let info = cgroups_rs::hierarchies::mountinfo_self();
    println!("is_cgroup2_unified_mode: {is_cgroup2_unified_mode}");
    println!("info: {info:?}");

    // println!("ifidx: {ifidx}");

    
    bump_memlock_rlimit()?;
    // ===========================================
    // let mut builder = NetpackSkelBuilder::default();
    // builder.obj_builder.debug(true);
    
    // let open = builder.open()?;
    
    
    // let mut skel = open.load()?;
    // skel.attach()?;
    // let sm_fd = skel.maps().sock_ops_map().fd();
    
    // let mut progs = skel.progs_mut();
   
    // let stream_parser_handler = progs.stream_parser_handler();
    // stream_parser_handler.attach_sockmap(sm_fd)?;
    // println!("attach type: {:?}", stream_parser_handler.attach_type());

    // progs.sk_msg_handler().attach_sockmap(sm_fd)?;
    
    // let socket_handler = progs.socket_handler();
    
    // println!("socket_handler: {socket_handler:?}");
    // println!("attach type: {:?}", socket_handler.attach_type());
    // let stream = TcpStream::connect("0.0.0.0:80").unwrap();
    
    // let target_socket_fd = open_fd()?;
    // // let prog_fd = socket_handler.fd();
    // let prog_fd = stream_parser_handler.fd();
    // let result = match unsafe {
    //     libc::setsockopt(target_socket_fd as c_int,
    //                SOL_SOCKET,
    //                SO_ATTACH_BPF,
    //                &prog_fd as *const _ as *const c_void,
    //                size_of_val(&prog_fd) as socklen_t)
    //     } {
    //     0 => Ok(()),
    //     _ => Err(Error::last_os_error().into()),
    // };

    // let perf = PerfBufferBuilder::new(skel.maps_mut().events())
    //     .sample_cb(handle_event)
    //     .lost_cb(handle_lost_events)
    //     .build()?;


    // ===========================================

    let mut socketfilter_builder = socketfilter::SocketfilterSkelBuilder::default();
    socketfilter_builder.obj_builder.debug(true);
    let socketfilter_open = socketfilter_builder.open()?;

    let mut socketfilter_skel = socketfilter_open.load()?;
    
    let socketfilter_map = socketfilter_skel.maps();
    let sock_hash = socketfilter_map.sock_hash();
    
    println!("sock_hash name:{:?}", sock_hash.name());
    println!("sock_hash map_type:{}", sock_hash.map_type());
    println!("sock_hash key_size:{}", sock_hash.key_size());
    println!("sock_hash value_size:{:?}", sock_hash.value_size());

    // let mut binding = socketfilter_skel.maps_mut();
    // let socke_map= binding.sock_hash();
    // socke_map.pin("/sys/fs/bpf/sock_ops_map")?;

    let map_fd =  socketfilter_skel.maps_mut().sock_hash().fd();
    let socketfilter_prog = socketfilter_skel.progs();
    let msg_prog = socketfilter_prog.sk_msg_handler();
    println!("msg_prog prog_type:{}", msg_prog.prog_type());
    println!("msg_prog attach_type:{}", msg_prog.attach_type());
    println!("msg_prog name:{:?}", msg_prog.name());
    println!("msg_prog section:{:?}", msg_prog.section());

    let stream_parser_handler = socketfilter_prog.stream_parser();
    println!("stream_parser_handler prog_type:{}", stream_parser_handler.prog_type());
    println!("stream_parser_handler attach_type:{}", stream_parser_handler.attach_type());
    println!("stream_parser_handler name:{:?}", stream_parser_handler.name());
    println!("stream_parser_handler section:{:?}", stream_parser_handler.section());

    let bpf_sockops = socketfilter_prog.bpf_sockops();
    println!("bpf_sockops prog_type:{}", bpf_sockops.prog_type());
    println!("bpf_sockops attach_type:{}", bpf_sockops.attach_type());
    println!("bpf_sockops name:{:?}", bpf_sockops.name());
    println!("bpf_sockops section:{:?}", bpf_sockops.section());

    // let _msg_prog = socketfilter_skel.progs_mut().sk_msg_handler().attach_sockmap(map_fd)?;
    let _parse_prog = socketfilter_skel.progs_mut().stream_parser().attach_sockmap(map_fd)?;

    // bpf_sockops_prog.pin("/sys/fs/bpf/bpf_sockops")?;

    let file = std::fs::OpenOptions::new()
            //.custom_flags(libc::O_DIRECTORY)
            //.create(true)
            .read(true)
            .write(false)
            .open("/sys/fs/cgroup/")?;
    let cgroup_fd = file.as_raw_fd();
    let _bpf_sockops = socketfilter_skel.progs_mut().bpf_sockops().attach_cgroup(cgroup_fd)?;
    // println!("attach type: {:?}", prog.bpf_sockops().attach_type());

    let perf = PerfBufferBuilder::new(socketfilter_skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
    // ===========================================

    // prog.bpf_sockops().attach_cgroup(cgroup_fd)
    // let ifidx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;
    
    // let mut skel_builder = RunqslowerSkelBuilder::default();
    // if opts.verbose {
    //     skel_builder.obj_builder.debug(true);
    // }

    // bump_memlock_rlimit()?;
    // let mut open_skel = skel_builder.open()?;

    // // Write arguments into prog
    // open_skel.rodata().min_us = opts.latency;
    // open_skel.rodata().targ_pid = opts.pid;
    // open_skel.rodata().targ_tgid = opts.tid;

    // // Begin tracing
    // let mut skel = open_skel.load()?;
    // skel.attach()?;
    // println!("Tracing run queue latency higher than {} us", opts.latency);
    // println!("{:8} {:16} {:7} {:14}", "TIME", "COMM", "TID", "LAT(us)");

    // loop {
    //     // perf.poll(Duration::from_millis(100))?;
    //     Duration::from_millis(100);
    // }
    // Ok(())
}
