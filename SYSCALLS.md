# Syscalls

### Note:
#### sudo cat /sys/kernel/debug/tracing/events/<filesystem>/<syscall>/format :: Use this command to fetch fields in a syscall

### Syscalls & Their Data
#### 1. tracepoint/syscalls/sys_enter_execve
##### A. All executed command PID

#### 2. tracepoint/sock/inet_sock_set_state
##### A. Log all TCP State transitions
##### B. Detect Successful Outbound Connections
##### C. Detect Failed Connections
##### D. Detect Connection Closures
##### E. Reconstruct Full TCP Lifecycle
##### F. Detect Listening Services
##### G. Detect Incoming Connections
##### H. Detect Reverse Shells
##### I. Detect Port Scans

#### 3. cgroup/connect4
##### 1. See Connection Attempts
##### 2. Detect Malware Intent
##### 3. Network Policy Enforcement
##### 4. Process Attribution

#### 3. cgroup/inet_bind4
##### 1. Detect New Services
##### 2. Detect Unauthorized Listeners
##### 3. Detect Privileged Port Usage
##### 4. Network Policy Enforcement
##### 5. Service Inventory

#### 4. tracepoint/sched/sched_process_exec
##### 1. Process Execution Logging
##### 2. Detect Reverse Shells
##### 3. Detect Malware Launch
##### 4. Detect LOLBins
##### 5. Detect Privilege Escalation Attempts
##### 6. Detect Persistence

##### Later understanding
u32 loc = ctx->__data_loc_filename;
u32 offset = loc & 0xFFFF; // mask opetation to extract lower 16 bits
char *filename = (void *)ctx + offset;
bpf_probe_read_kernel_str(
    e->filename,
    sizeof(e->filename),
    filename
);