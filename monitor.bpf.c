//go:build ignore
# include "vmlinux.h"
# include <bpf/bpf_helpers.h>
# include <bpf/bpf_core_read.h>
# include <bpf/bpf_tracing.h>
# include <bpf/bpf_endian.h>
#define AF_INET 2

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    char comm[16];
    __u8 event_type;          // 1 : file_open, 2 : connect, 3 : exec later 
    char filename[256];     // used for file_open
    __u32 daddr;             // used for connect
    __u16 dport;            // used for connect
    char command[256];
    __u32 policy_type;
} __attribute__((packed));

/*
struct trace_event_raw_sched_process_fork {
    __u64 unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};
*/

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

/* PID namespace of AgentGuard (same ns as the agent). Lookups must
 * use this ns — bpf_get_current_pid_tgid() is init-ns and misses in Docker. */
volatile const __u64 pidns_dev = 0;
volatile const __u64 pidns_ino = 0;

static __always_inline int current_nspids(__u32 *tid, __u32 *tgid)
{
	struct bpf_pidns_info ns = {};

	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return -1;
	*tid = ns.pid;
	*tgid = ns.tgid;
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx){
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;

    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!tracked) 
        return 0; //not a target, ignore

    // reserve space in ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    
    if (!e)
        return 0; 

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = 1; 
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    e->daddr = 0;
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx){
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);

    if(!tracked)
        return 0; 

    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]);
    
    if (addr.sin_family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = 2;
    e->filename[0] = 0;
    e->daddr = addr.sin_addr.s_addr;
    e->dport = bpf_ntohs(addr.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child)
{
	/* Map keys are process TGIDs. sched_process_fork also fires for
	 * clone() threads — inserting those TIDs filled the 1024-slot map
	 * and new rm children were never tracked. */
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	__u32 child_tid  = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	__u8 one = 1;

	if (child_tid != child_tgid)
		return 0;

	if (!bpf_map_lookup_elem(&tracked_pids, &parent_tgid))
		return 0;

	bpf_map_update_elem(&tracked_pids, &child_tgid, &one, BPF_ANY);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = child_tgid;
	e->ppid = parent_tgid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->event_type = 4;
	e->filename[0] = 0;
	e->daddr = 0;
	e->dport = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx){
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);

    if (!tracked)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = 0; // Not available here, fork event already captured it
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = 3;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);
    e->daddr = 0;
    e->dport = 0;   

    // Grab pointers to the first 3 arguments
    const char *argv[3] = {};
    bpf_probe_read_user(&argv, sizeof(argv), (void *)ctx->args[1]);

    // Clear out any old memory in the command buffer
    __builtin_memset(e->command, 0, sizeof(e->command));
    __u32 offset = 0;

    // Safely loop through and stitch them together with spaces
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (!argv[i]) {
            bpf_printk("DEBUG argv[%d] is NULL, breaking\n", i);
            break;
        } 
        //bpf_printk("DEBUG argv[%d] ptr=%llx\n", i, (unsigned long long)argv[i]);

        __u32 safe_offset = offset & 0xff;   // mask RIGHT before use — this is what the verifier can actually prove
        if (safe_offset > 192) break;

        int len = bpf_probe_read_user_str(&e->command[safe_offset], 64, argv[i]);
        //bpf_printk("DEBUG argv[%d] len=%d\n", i, len);
        if (len > 0) {
            __u32 space_offset = (safe_offset + (len - 1)) & 0xff;   // mask again, immediately before use
            e->command[space_offset] = ' ';
            offset = space_offset + 1;
        }
    } 
    bpf_printk("DEBUG command buffer: [%s]\n", e->command);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx){
	__u32 tid, tgid;

	if (current_nspids(&tid, &tgid))
		return 0;

	/* Drop a leaked thread-TID key if we ever inserted one. Do not
	 * delete the process TGID when a worker thread exits. */
	bpf_map_delete_elem(&tracked_pids, &tid);
	if (tid == tgid)
		bpf_map_delete_elem(&tracked_pids, &tgid);
	return 0;
}