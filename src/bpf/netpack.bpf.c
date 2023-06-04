// #include <linux/bpf.h>
// #include <linux/filter.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/in.h> 
// #include <linux/tcp.h>

// /* Attach to device en0 */ 
// SEC("socket")
// int bpf_prog(struct __sk_buff *skb)
// {
//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;

//     /* Get IP header and check it's IPv4 */
//     struct iphdr *iph = data + sizeof(struct ethhdr);
//     if (iph + 1 > data_end) 
//         return 0;
        
//     if (iph->version != 4)
//         return 0;
    
//     /* Get TCP header */
//     struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
//     if (tcph + 1 > data_end)
//         return 0;

//     /* Get source and destination IP */
//     uint32_t src_ip = iph->saddr; 
//     uint32_t dst_ip = iph->daddr;

//     /* Get source and destination ports */
//     uint16_t src_port = tcph->source;
//     uint16_t dst_port = tcph->dest; 
    
//     /* Output via bpf_trace_printk() */
//     bpf_trace_printk("%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n", 
//             src_ip & 0xFF, (src_ip >> 8) & 0xFF,  
//             (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF,
//             src_port,
//             dst_ip & 0xFF, (dst_ip >> 8) & 0xFF,  
//             (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF,
//             dst_port);

//     return 0;
// }
// #include <vmlinux.h>

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
