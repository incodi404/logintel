#include "/home/dipankar/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 1 << 24 means 16 MB
} events SEC(".maps");

// tracepoint hook
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("EXECVE HIT");
    
    // declaring pointer of event
    struct event *e;

    // allocation of RING_BUF memory
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // fetch event and fill that to event struct
    e->pid = bpf_get_current_pid_tgid() >> 32; // upper 32 bit is PID and lower 32 is TGID, I am taking PID

    // send event to userspace
    bpf_ringbuf_submit(e, 0);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";