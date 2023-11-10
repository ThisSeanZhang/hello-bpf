#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#ifndef STACK_STORAGE_SIZE
#define STACK_STORAGE_SIZE 16384
#endif

#define _KERNEL(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_core_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

// #define _(P)                                                                   \
// 	({                                                                     \
// 		typeof(P) val;                                                 \
// 		bpf_probe_read(&val, sizeof(val), &(P));                \
// 		val;                                                           \
// 	})

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
	__u32 pid; // 4
	__u32 cpu_id; // 4
	char comm[TASK_COMM_LEN]; // 16
	__s32 kstack_sz; // 8
	__s32 ustack_sz; // 8
	stack_trace_t kstack; // 128 * 8  1024
	stack_trace_t ustack; // 128 * 8  1024
    u64 time_delta; // 8
    u64 relative_time; // 8
    u32 on_time;
};

struct stacktrace_event _stacktrace_event = {};
// struct key_t {
//     u32 pid;
//     u32 tgid;
//     int user_stack_id;
//     int kernel_stack_id;
//     char name[TASK_COMM_LEN];
// };

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, struct key_t);
// 	__type(value, u32);
// } counts SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value,u64);
} start SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
// 	__uint(max_entries, 10240);
// 	__type(key, STACK_STORAGE_SIZE);
// 	__type(value, u32);
// } stack_traces SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024);
// } events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} s_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
    __type(key, u32);
    __type(value, struct stacktrace_event);
} write_buffer_heap SEC(".maps");

SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(k_task_switch, struct task_struct *prev)
{
    u32 pid, tgid;
    u64 ts, *tsp;

    bpf_core_read(&pid, sizeof(pid), &prev->pid);
    bpf_core_read(&tgid, sizeof(tgid), &prev->tgid);
    // pid = _KERNEL(prev->pid);
    // tgid = _KERNEL(prev->tgid);

    // record previous thread sleep time
    // if ((THREAD_FILTER) && (STATE_FILTER)) {
    //     ts = bpf_ktime_get_ns();
    //     start.update(&pid, &ts);
    // }


	int cpu_id = bpf_get_smp_processor_id();

    if (tgid == 282632) {
        // 
        tsp = bpf_map_lookup_elem(&start, &pid);
        ts = bpf_ktime_get_ns();
        if (tsp == 0) {
            goto update_perv_time;
        }
        if (*tsp > ts) {
            bpf_printk("warn start > end");
            goto update_perv_time;
        }
        u64 t_start = *tsp;
        u64 delta = ts - t_start;
        delta = delta / 1000;
        if (delta < 10) {
            goto update_perv_time;
        }

        struct stacktrace_event *event;

        int zero = 1;
        event = bpf_map_lookup_elem(&write_buffer_heap, &zero);
            // event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;

        event->pid = pid;
        event->cpu_id = cpu_id;

        if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
            event->comm[0] = 0;

        event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

        event->ustack_sz =
            bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
        event->time_delta = delta;
        event->relative_time = t_start;
        event->on_time = 1;
        bpf_perf_event_output(ctx, &s_events, BPF_F_CURRENT_CPU, event, sizeof(*event));

        update_perv_time:
            bpf_printk("update off time start");
            bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;


    if (tgid != 282632) {
        return 0;
    }

    tsp = bpf_map_lookup_elem(&start, &pid);

    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    // bpf_map_delete_elem(&start, &pid);
    if (t_start > t_end) {
        bpf_printk("warn start > end");
        return 0;
    }
    u64 delta = t_end - t_start;
    delta = delta / 1000;
    if (delta < 10) {
        return 0;
    }
    // if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
    //     return 0;
    // }

    // create map key
    // struct key_t key = {};

    // key.pid = pid;
    // key.tgid = tgid;
    // key.user_stack_id = USER_STACK_GET;
    //  = KERNEL_STACK_GET;
    // key.kernel_stack_id = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	// event->ustack_sz =
	// 	bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    // bpf_get_current_comm(&key.name, sizeof(key.name));

    // counts.increment(key, delta);
	struct stacktrace_event *event;

    int zero = 0;
    event = bpf_map_lookup_elem(&write_buffer_heap, &zero);
    	// event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cpu_id = cpu_id;

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz =
		bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
    event->time_delta = delta;
    event->relative_time = t_start;
    event->on_time = 2;
    bpf_perf_event_output(ctx, &s_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	// bpf_ringbuf_submit(event, 0);
    bpf_map_update_elem(&start, &pid, &t_end, BPF_ANY);

	return 0;
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
