#include "vmlinux.h"
#include "netpack.h"

// #include <stddef.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// #define IP_MF	  0x2000
// #define IP_OFFSET 0x1FFF

extern int LINUX_KERNEL_VERSION __kconfig;

char LICENSE[] SEC("license") = "MIT";

struct so_event _event = {};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events
SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024);
// } rb SEC(".maps");

// static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
// {
// 	__u16 frag_off;

// 	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
// 	frag_off = __bpf_ntohs(frag_off);
// 	return frag_off & (IP_MF | IP_OFFSET);
// }

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
 char msg[] = "Hello, World!";
//  __u16 port; // enough to hold a 16-bit port number
//  bpf_probe_read_kernel(&port, sizeof(port), &skb->local_port); // read the port value
//  port = htons(port); // convert to network byte order
 bpf_trace_printk(msg, sizeof(msg)); // print the 
//  bpf_trace_printk(skb, sizeof(skb)); // print the 
	// struct so_event event = {
	// 	.src_addr = 10,
	// 	.dst_addr = 20,
	// 	};
	
	// bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));


	return skb->len;
}

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
	
	__type(key, u32);
	__type(value, u32);
} sock_ops_map
SEC(".maps");


SEC("sk_msg")
int sk_msg_handler(struct sk_msg_md *msg) {
    char p_msg[] = "Hello, sk_msg!";
    bpf_trace_printk(p_msg, sizeof(p_msg)); 

	return SK_PASS;
}

SEC("sk_skb/stream_parser")
int stream_parser_handler(struct __sk_buff *skb) {
 char p_msg[] = "Hello, stream_parser!";
//  __u16 port; // enough to hold a 16-bit port number
//  bpf_probe_read_kernel(&port, sizeof(port), &skb->local_port); // read the port value
//  port = htons(port); // convert to network byte order
 bpf_trace_printk(p_msg, sizeof(p_msg)); // print the 
//  bpf_trace_printk(skb, sizeof(skb)); // print the 
	// struct so_event event = {
	// 	.src_addr = 10,
	// 	.dst_addr = 20,
	// 	};
	
	// bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));


	return skb->len;
}
