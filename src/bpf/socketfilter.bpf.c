#include "vmlinux.h"
#include "netpack.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/udp.h>


extern int LINUX_KERNEL_VERSION __kconfig;

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))


// #define bpf_printk(fmt, ...)					\
// ({								\
// 	       char ____fmt[] = fmt;				\
// 	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
// 				##__VA_ARGS__);			\
// })

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u8  family;
    __u8  pad1;   // this padding required for 64bit alignment
    __u16 pad2;   // else ebpf kernel verifier rejects loading of the program
    __u32 pad3;
    __u32 sport;
    __u32 dport;
} __attribute__((packed));

// 定义一个 eBPF map，用于存储 socket 的 cookie 和数据
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
} sock_hash SEC(".maps");

struct so_event _event = {};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dip4 = ops->remote_ip4;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = FORCE_READ(ops->remote_port) >> 16;
}


static __always_inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    int ret;

    extract_key4_from_ops(skops, &key);

    ret = bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST);
    if (ret != 0) {
        //bpf_printk("sock_hash_update() failed, ret: %d\n", ret);
    }

    //bpf_printk("sockmap: op %d, port %d --> %d\n",
     //          skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

// 定义一个 eBPF 程序，用于处理 TCP 事件
SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops)
{
	// struct so_event event = {
	// 	.src_addr = 10,
	// 	.dst_addr = 20,
	// 	};
	
	// bpf_perf_event_output(skops, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    char p_msg[] = "Hello, sockops!";
    bpf_trace_printk(p_msg, sizeof(p_msg)); // print the 
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (skops->family == 2) { //AF_INET
                bpf_sock_ops_ipv4(skops);
            }
            break;
        default:
            break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";

// struct packet_meta {
//     __u32 src_ip;
//     __u32 dst_ip;
//     __u16 src_port;
//     __u16 dst_port;
//     __u32 data_len;
// };

SEC("sk_msg")
int sk_msg_handler(struct sk_msg_md *msg) {
    char p_msg[] = "Hello, sk_msg!";
//  __u16 port; // enough to hold a 16-bit port number
//  bpf_probe_read_kernel(&port, sizeof(port), &skb->local_port); // read the port value
//  port = htons(port); // convert to network byte order
    bpf_trace_printk(p_msg, sizeof(p_msg)); // print the 

    // int cpu = bpf_get_smp_processor_id();
    // 定义两个指针 data 和 data_end，分别指向 skb->data 和 skb->data_end
    // struct packet_meta meta;
    // meta.src_ip = iph->saddr;
    // meta.dst_ip = iph->daddr;
    // meta.src_port = udp->source;
    // meta.dst_port = udp->dest;
    // meta.data_len = udp->len;
    // // 使用 bpf_perf_event_output 函数将 data 的数据写入 perf ring buffer
    // bpf_perf_event_output(msg, &events, BPF_F_CURRENT_CPU, &meta, sizeof(meta));
    // 允许消息通过
//  bpf_trace_printk(skb, sizeof(skb)); // print the 
	// struct so_event event = {
	// 	.src_addr = 10,
	// 	.dst_addr = 20,
	// 	};
	
	// bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));


	return SK_PASS;
}

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    char p_msg[] = "Hello, stream_parser!";
    bpf_trace_printk(p_msg, sizeof(p_msg)); // print the 
	return 0;
}


