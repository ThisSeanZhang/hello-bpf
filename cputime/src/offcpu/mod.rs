use std::io::Error;
use std::mem;
use std::path::PathBuf;
use std::time::Duration;

use blazesym::Addr;
use blazesym::symbolize;

// use blazesym::symbolize::CodeInfo;
// use blazesym::symbolize::Sym;
// use blazesym::symbolize::Symbolized;
use clap::ArgAction;
use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use nix::unistd::close;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;
use libbpf_rs::PerfBufferBuilder;
mod offcputime {
    include!(concat!(env!("OUT_DIR"), "/offcputime.skel.rs"));
}
use crate::profile::syscall;

use offcputime::*;

use plain::Plain;

unsafe impl Plain for offcputime_bss_types::stacktrace_event {}


const MAX_STACK_DEPTH: usize = 128;
const TASK_COMM_LEN: usize = 16;

// A Rust version of stacktrace_event in profile.h
#[repr(C)]
struct stacktrace_event {
    pid: u32,
    cpu_id: u32,
    comm: [u8; TASK_COMM_LEN],
    kstack_size: i32,
    ustack_size: i32,
    kstack: [u64; MAX_STACK_DEPTH],
    ustack: [u64; MAX_STACK_DEPTH],
    time_delta: u64,
    relative_time: u64,
}

// const ADDR_WIDTH: usize = 16;
// fn print_frame(name: &str, addr_info: Option<(Addr, Addr, usize)>, code_info: &Option<CodeInfo>) {
//     let code_info = code_info.as_ref().map(|code_info| {
//         let path = code_info.to_path();
//         let path = path.display();
        
//         match (code_info.line, code_info.column) {
//             (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
//             (Some(line), None) => format!(" {path}:{line}"),
//             (None, _) => format!(" {path}"),
//         }
//     });

//     if let Some((input_addr, addr, offset)) = addr_info {
//         // If we have various address information bits we have a new symbol.
//         println!(
//             "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
//             code_info = code_info.as_deref().unwrap_or(""),
//             width = ADDR_WIDTH
//         )
//     } else {
//         // Otherwise we are dealing with an inlined call.
//         println!(
//             "{:width$}  {name}{code_info} [inlined]",
//             " ",
//             code_info = code_info
//                 .map(|info| format!(" @{info}"))
//                 .as_deref()
//                 .unwrap_or(""),
//             width = ADDR_WIDTH
//         )
//     }
// }

fn init_perf_monitor(freq: u64) -> Vec<i32> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = -1;
    let buf: Vec<u8> = vec![0; mem::size_of::<syscall::perf_event_attr>()];
    let mut attr = unsafe {
        Box::<syscall::perf_event_attr>::from_raw(
            buf.leak().as_mut_ptr() as *mut syscall::perf_event_attr
        )
    };
    attr._type = syscall::PERF_TYPE_HARDWARE;
    attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
    attr.config = syscall::PERF_COUNT_HW_CPU_CYCLES;
    attr.sample.sample_freq = freq;
    attr.flags = 1 << 10; // freq = 1
    (0..nprocs)
        .map(|cpu| {
            let fd = syscall::perf_event_open(attr.as_ref(), pid, cpu as i32, -1, 0);
            fd as i32
        })
        .collect()
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &mut libbpf_rs::Program,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
}

// Pid 0 means a kernel space stack.
fn show_stack_trace(stack: &[u64], symbolizer: &symbolize::Symbolizer, pid: u32) {
    let converted_stack;
    // The kernel always reports `u64` addresses, whereas blazesym uses `usize`.
    // Convert the stack trace as necessary.
    let stack = if mem::size_of::<blazesym::Addr>() != mem::size_of::<u64>() {
        converted_stack = stack
            .iter()
            .copied()
            .map(|addr| addr as blazesym::Addr)
            .collect::<Vec<_>>();
        converted_stack.as_slice()
    } else {
        // SAFETY: `Addr` has the same size as `u64`, so it can be trivially and
        //         safely converted.
        unsafe { mem::transmute::<_, &[blazesym::Addr]>(stack) }
    };

    let src = if pid == 0 {
        symbolize::Source::from(symbolize::Kernel::default())
    } else {
        symbolize::Source::from(symbolize::Process::new(pid.into()))
    };

    let syms = match symbolizer.symbolize(&src, stack) {
        Ok(syms) => syms,
        Err(err) => {
            eprintln!("  failed to symbolize addresses: {err:#}");
            return;
        }
    };

    // for (i, (addr, syms)) in stack.iter().zip(syms).enumerate() {
    //     let mut addr_fmt = format!(" {i:2} [<{addr:016x}>]");
    //     match syms {
    //         Symbolized::Sym(Sym {
    //             name,
    //             addr,
    //             offset,
    //             code_info,
    //             inlined,
    //             ..
    //         }) => {

    //             // println!("{name}");
    //             print_frame(&name, Some((addr, addr, offset)), &code_info);
    //             // for frame in inlined.iter() {
    //             //     print_frame(&frame.name, None, &frame.code_info);
    //             // }
    //         }
    //         Symbolized::Unknown => {
    //             println!("{addr_fmt}");
    //         }
    //     }
    // }

    for (i, (addr, syms)) in stack.iter().zip(syms).enumerate() {
    let mut addr_fmt = format!(" {i:2} [<{addr:016x}>]");
    if syms.is_empty() {
        println!("{addr_fmt}")
    } else {
        for (i, sym) in syms.into_iter().enumerate() {
            if i == 1 {
                addr_fmt = addr_fmt.replace(|_c| true, " ");
            }

            let path = match (sym.dir, sym.file) {
                (Some(dir), Some(file)) => Some(dir.join(file)),
                (dir, file) => dir.or_else(|| file.map(PathBuf::from)),
            };

            let src_loc = if let (Some(path), Some(line)) = (path, sym.line) {
                if let Some(col) = sym.column {
                    format!(" {}:{line}:{col}", path.display())
                } else {
                    format!(" {}:{line}", path.display())
                }
            } else {
                String::new()
            };

            let symbolize::Sym {
                name, addr, offset, ..
            } = sym;

            println!("{addr_fmt} {name} @ {addr:#x}+{offset:#x}{src_loc}");
        }
    }
    }
}

fn event_handler(symbolizer: &symbolize::Symbolizer, data: &[u8]) -> ::std::os::raw::c_int {
    // if data.len() != mem::size_of::<stacktrace_event>() {
    //     eprintln!(
    //         "Invalid size {} != {}",
    //         data.len(),
    //         mem::size_of::<stacktrace_event>()
    //     );
    //     return 1;
    // }

    // let event = unsafe { &*(data.as_ptr() as *const stacktrace_event) };
    let mut event = offcputime_bss_types::stacktrace_event::default();
    // println!("data len: {}", data.len());
    // println!("data len: {:?}", data);
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

    if event.on_time == 1 {
        println!("on time: {}, {}", event.on_time, event.time_delta);
    } else {
        println!("off time: {}, {}", event.on_time, event.time_delta);
    }

    if event.kstack_sz <= 0 && event.ustack_sz <= 0 {
        return 1;
    }

    let binding = event.comm.clone().iter().map(|e| *e as u8).collect::<Vec<u8>>();
    let comm = std::str::from_utf8(&binding)
        .or::<Error>(Ok("<unknown>"))
        .unwrap();
    println!("COMM: {} (pid={}) @ CPU {}", comm, event.pid, event.cpu_id);

    if event.ustack.len() <= 2 {
        return 0;
    }

    if event.kstack_sz > 0 {
        println!("Kernel:");
        show_stack_trace(
            &event.kstack[0..(event.kstack_sz as usize / mem::size_of::<u64>())],
            symbolizer,
            0,
        );
    } else {
        println!("No Kernel Stack");
    }

    if event.ustack_sz > 0 {
        println!("Userspace:");
        show_stack_trace(
            &event.ustack[0..(event.ustack_sz as usize / mem::size_of::<u64>())],
            symbolizer,
            event.pid,
        );
    } else {
        println!("No Userspace Stack");
    }

    println!();
    0
}

#[derive(Parser, Debug)]
struct Args {
    /// Sampling frequency
    #[arg(short, default_value_t = 1)]
    freq: u64,
    /// Increase verbosity (can be supplied multiple times).
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbosity: u8,
}

pub fn start() -> Result<(), Error> {
    let args = Args::parse();
    let level = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_span_events(FmtSpan::FULL)
        .with_timer(SystemTime)
        .finish();
    let () = set_global_subscriber(subscriber).expect("failed to set tracing subscriber");

    let freq = if args.freq < 1 { 1 } else { args.freq };

    let symbolizer = symbolize::Symbolizer::new();

    let skel_builder = OffcputimeSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    let _kprobe = skel
    .progs_mut()
    .k_task_switch()
    .attach_kprobe(false, "finish_task_switch.isra.0").unwrap();


    // let pefds = init_perf_monitor(freq);
    // let _links = attach_perf_event(&pefds, skel.progs_mut().k_task_switch());

    let perf = PerfBufferBuilder::new(skel.maps_mut().s_events())
    .sample_cb(|_cpu: i32, data: &[u8]| {
        event_handler(&symbolizer, data);
    })
    .build().unwrap();
    loop {
        perf.poll(Duration::from_millis(100)).unwrap();
    }
    // let mut builder = libbpf_rs::RingBufferBuilder::new();
    // let binding = skel.maps();
    // builder
    //     .add(binding.events(), move |data| {
    //         event_handler(&symbolizer, data)
    //     })
    //     .unwrap();
    // let ringbuf = builder.build().unwrap();
    // while ringbuf.poll(Duration::MAX).is_ok() {}

    // for pefd in pefds {
    //     close(pefd)?;
    // }

    Ok(())
}
