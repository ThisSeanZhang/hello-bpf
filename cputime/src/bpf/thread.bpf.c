#include "vmlinux.h"
// #include <openssl/ssl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


#define socklen_t size_t


typedef struct ssl_st SSL;
// SEC("uprobe//usr/lib/libssl.so.3:SSL_write")
SEC("uprobe")
int BPF_UPROBE(catch_ssl_write, SSL *ssl,const char *buf, int num) {
    bpf_printk("SSL_write message len: %u", num);
	bpf_printk("message: %s", buf);
    return 0;
}

static u32 get_tid()
{
	u64 tgid = bpf_get_current_pid_tgid();
	pid_t pid = tgid >> 32;
	return (u32)tgid;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	u32 tid = get_tid();

	
    bpf_printk("Debug: ===> pid: %u create a tcp connect", tid);
	return 0;
};

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	bpf_printk("packet size: %d", pkt_sz);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
