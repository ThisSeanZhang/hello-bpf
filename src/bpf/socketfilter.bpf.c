#include "vmlinux.h"
#include "netpack.h"

// #include <stddef.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


extern int LINUX_KERNEL_VERSION __kconfig;

// 定义一个结构体，用于存储 socket 的数据
struct sock_data {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 bytes_sent;
};

// 定义一个 eBPF map，用于存储 socket 的 cookie 和数据
struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(max_entries, 10240);
		__type(key, u32);
		__type(value, struct sock_data);
} sock_map SEC(".maps");

// 定义一个 eBPF 程序，用于处理 TCP 事件
SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops)
{
    int op = (int) skops->op;
    struct sock_data *data;
    u64 cookie;

    // 只处理指定端口的 TCP 连接
    if (skops->local_port != 80)
        return 0;

    char msg[] = "Hello, World!";
    bpf_trace_printk(msg, sizeof(msg)); // print the 
    // // 获取 socket 的 cookie
    // cookie = bpf_get_socket_cookie(skops);

    // switch (op) {
    //     case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    //     case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    //         // TCP 连接建立时，分配并初始化一个 sock_data 结构体，并存入 map 中
    //         data = bpf_map_lookup_elem(&sock_map, &cookie);
    //         if (!data) {
    //             data = bpf_map_alloc_elem(&sock_map, &cookie);
    //             if (!data)
    //                 return 0;
    //             data->src_ip = skops->local_ip4;
    //             data->dst_ip = skops->remote_ip4;
    //             data->src_port = skops->local_port;
    //             data->dst_port = skops->remote_port;
    //             data->bytes_sent = 0;
    //         }
    //         // 设置 socket 的回调标志，让程序在每个 TCP 事件发生时被调用
    //         bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_ALL_CB_FLAGS);
    //         break;

    //     case BPF_SOCK_OPS_TX_CB:
    //         // TCP 连接发送数据时，更新 sock_data 结构体中的 bytes_sent 字段
    //         data = bpf_map_lookup_elem(&sock_map, &cookie);
    //         if (data) {
    //             data->bytes_sent += skops->bytes_acked;
    //         }
    //         break;

    //     case BPF_SOCK_OPS_CLOSE_CB:
    //         // TCP 连接关闭时，从 map 中删除 sock_data 结构体，并将其发送到用户空间程序进行处理或分析
    //         data = bpf_map_lookup_elem(&sock_map, &cookie);
    //         if (data) {
    //             bpf_skb_event_output(skops, &sock_map, BPF_F_CURRENT_CPU,
    //                                  data, sizeof(*data));
    //             bpf_map_delete_elem(&sock_map, &cookie);
    //         }
    //         break;

    //     default:
    //         break;
    // }

    return 0;
}

char _license[] SEC("license") = "MIT";



