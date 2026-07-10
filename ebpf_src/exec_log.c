#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct exec_event {
    char filename[64];

    __u32 pid;
    __u32 old_pid;
    __u32 uid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    bpf_printk("EXEC HIT");
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->old_pid = ctx->old_pid;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    u32 loc = ctx->__data_loc_filename;
    u32 offset = loc & 0xFFFF; // mask opetation to extract lower 16 bits
    char *filename = (void *)ctx + offset;

    bpf_probe_read_kernel_str(
        e->filename,
        sizeof(e->filename),
        filename
    );

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";