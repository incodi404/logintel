#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// sock/inet_sock_set_state
struct isss_event
{
    void *skaddr; // kernel socket pointer
    int oldstate;
    int newstate;
    __u16 sport;  // src port
    __u16 dport;  // dest port
    __u16 family; // addr family
    __u16 protocol;
    __u8 saddr[4];     // src addr/ipv4
    __u8 daddr[4];     // dest addr/ipv4
    __u8 saddr_v6[16]; // src addr/ipv6
    __u8 daddr_v6[16]; // dest addr/ipv6
    __u32 pid;
};

// cgroup/connect4 & cgroup/bind4
struct connect4_event
{
    __u32 user_family;

    // dest
    __u32 user_ip4; // (8 bytes * 4)
    __u32 user_port;

    // These are not provided here and also 
    //there is no importance of these fields
    /*
    __u32 user_ip6[4];
    __u32 msg_src_ip4;
    __u32 msg_src_ip6[4];
    */

    __u32 family;
    __u32 type;
    __u32 protocol;

    __u32 pid;
    __u32 uid;
};

// global
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(
    struct trace_event_raw_inet_sock_set_state *ctx)
{
    // defining mem
    struct isss_event *e;

    // allocation of ringbuf memory
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    // getting all the data from ctx
    e->skaddr = ctx->skaddr;

    // this all are integer values. We have direct access from ctx that's because
    // we don't need bpf_probe_read_kernel().
    e->oldstate = ctx->oldstate;
    e->newstate = ctx->newstate;
    e->family = ctx->family;
    e->protocol = ctx->protocol;
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // copying ports
    // e->sport = bpf_ntohs(ctx->sport);
    // e->dport = bpf_ntohs(ctx->dport);
    e->sport = ctx->sport;
    e->dport = ctx->dport;

    // copying IPs
    bpf_probe_read_kernel(
        e->saddr, sizeof(e->saddr), &ctx->saddr);
    bpf_probe_read_kernel(
        e->daddr, sizeof(e->daddr), &ctx->daddr);
    bpf_probe_read_kernel(
        e->saddr_v6, sizeof(e->saddr_v6), &ctx->saddr_v6);
    bpf_probe_read_kernel(
        e->daddr_v6, sizeof(e->daddr_v6), &ctx->daddr_v6);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx)
{
    // IMPORTANT
    // "return 1" is non-blocking connections
    // "return 0" is blocking connections
    // This hook will create direct effect on the connections

    // allocation of memory
    struct connect4_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        return 1; // not blocking any connection
    }

    // copying everything
    // copying port
    e->user_port = bpf_ntohs(ctx->user_port);

    e->user_family = ctx->user_family;
    e->user_ip4 = ctx->user_ip4;
    e->family = ctx->family;
    e->type = ctx->type;
    e->protocol = ctx->protocol;

    // getting pid & uid
    e->pid = bpf_get_current_pid_tgid() >> 32; // upper 32 bit
    e->uid = (__u32)bpf_get_current_uid_gid(); // lower 32 bit

    bpf_ringbuf_submit(e, 0); // sending data

    return 1;
}

SEC("cgroup/bind4")
int handle_bind4(struct bpf_sock_addr *ctx)
{
    // IMPORTANT
    // "return 1" is non-blocking connections
    // "return 0" is blocking connections
    // This hook will create direct effect on the connections

    // allocation of memory
    struct connect4_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        return 1; // not blocking any connection
    }

    // copying everything
    // copying port
    e->user_port = bpf_ntohs(ctx->user_port);

    e->user_family = ctx->user_family;
    e->user_ip4 = ctx->user_ip4;
    e->family = ctx->family;
    e->type = ctx->type;
    e->protocol = ctx->protocol;

    // getting pid & uid
    e->pid = bpf_get_current_pid_tgid() >> 32; // upper 32 bit
    e->uid = (__u32)bpf_get_current_uid_gid(); // lower 32 bit

    bpf_ringbuf_submit(e, 0); // sending data

    return 1;
}

char LICENSE[] SEC("license") = "GPL";