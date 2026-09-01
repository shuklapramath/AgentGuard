//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_PATH_LEN 256        // max possible length of a file path 
#define MAX_PATTERN_LEN 64      // max possible patterns 
#define HALF_LEN 128
#define EPERM 1
#define AF_INET 2
#define AF_UNIX 1
#define AF_INET6 10
#define SOCK_RAW 3
#define AF_PACKET 17

char LICENSE[] SEC("license") = "GPL";

/* set on the SPEC, before load - .rodata is frozen at load time */
volatile const __u32 proxy_addr_host = 0;   /* host order, e.g. 0x7f000001 */
volatile const __u16 proxy_port_host = 0;   /* host order */
volatile const __u32 dns_addr_host   = 0;   /* 0x7f000035 -> 127.0.0.53 */
volatile const __u32 network_policy_id = 0;

/* PID namespace of AgentGuard (same ns as the agent). LSM lookups must
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

/* NOT const: lives in .bss, writable after load. This is the kill switch. */
__u8 enforce_network    = 0;
__u8 allow_local_dns    = 0;
__u8 enforce_workspace  = 0;

// Reuse tracked_pids from monitor.bpf.c via MapReplacements, same pattern as ssl_probe.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

// Dynamic Hash Map containing the blocked path
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);     // The canonical file path
    __type(value, __u32);         // The policy ID to return to Go
} blocked_paths_map SEC(".maps");

// Blocked path suffixes (e.g. "/.env"). ARRAY slots filled by Go applyPathPatterns.
// Exact path_ends_with match — avoids verifier blow-up from nested substring scans.
#define MAX_PATH_RULES 16

struct path_pattern_entry {
	char pattern[MAX_PATTERN_LEN];
	__u32 policy_id;
	__u8  pattern_len;
	__u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PATH_RULES);
	__type(key, __u32);
	__type(value, struct path_pattern_entry);
} blocked_path_patterns SEC(".maps");

/* Prefix allow-list for workspace confinement. 24 slots so the starter
 * YAML (system prefixes + ~/.claude + ~/.local) fits; 16 was too small. */
#define MAX_ALLOW_PREFIXES 24

struct prefix_entry {
	char pattern[MAX_PATTERN_LEN];
	__u32 policy_id;
	__u8  pattern_len;
	__u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ALLOW_PREFIXES);
	__type(key, __u32);
	__type(value, struct prefix_entry);
} allowed_path_prefixes SEC(".maps");

/* Project root may be longer than 64 bytes. Dedicated 256-byte slot. */
struct workspace_root_entry {
	char prefix[MAX_PATH_LEN];
	__u32 prefix_len;
	__u32 policy_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct workspace_root_entry);
} workspace_root SEC(".maps");

/* Scratch path for file_open: map value (not stack) so path[path_len - pat_len + i]
 * is a legal variable-offset read for the verifier. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH_LEN]);
} file_open_path SEC(".maps");

// Blocked command basenames as path suffixes (e.g. "/rm", "/dd").
// ARRAY + path_ends_with — same matcher as credential path rules.
#define MAX_CMD_RULES 16

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CMD_RULES);
	__type(key, __u32);
	__type(value, struct path_pattern_entry);
} blocked_command_patterns SEC(".maps");

/* Scratch path for check_exec (d_path / bprm->filename). Same verifier reason
 * as file_open_path: variable-offset reads must be from a map value. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH_LEN]);
} exec_path SEC(".maps");

// Ring buffer to report violations back to userspace 
struct violation_event{
    __u64 timestamp_ns;
    __u32 pid;
    __u32 policy_type;   // policy ID from map / network_policy_id constant
    char typed_comm[16];
    char canonical_path[256];
    char detail[256];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} violations SEC(".maps");

/*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps"); */

/* Exact suffix match. Mask indices before map loads so the verifier sees
 * umax < value_size (bare if (idx >= MAX_PATH_LEN) is not enough for
 * path_len - pat_len + i). */
static __always_inline int path_ends_with(const char *path, __u32 path_len,
					  const char *pat, __u32 pat_len)
{
	__u32 i, idx, pi;

	if (pat_len == 0 || pat_len > MAX_PATTERN_LEN)
		return 0;
	if (path_len >= MAX_PATH_LEN || path_len < pat_len)
		return 0;

	for (i = 0; i < MAX_PATTERN_LEN; i++) {
		if (i >= pat_len)
			break;

		idx = path_len - pat_len + i;
		idx &= (MAX_PATH_LEN - 1);

		pi = i & (MAX_PATTERN_LEN - 1);

		if (path[idx] != pat[pi])
			return 0;
	}
	return 1;
}

/* Exact basename when execve("rm") — filename has no slash; pattern is "/rm". */
static __always_inline int path_is_basename(const char *path, __u32 path_len,
					    const char *pat, __u32 pat_len)
{
	__u32 i, idx, pi;

	if (pat_len < 2 || pat[0] != '/')
		return 0;
	if (path_len + 1 != pat_len)
		return 0;
	if (path_len >= MAX_PATH_LEN || path_len > MAX_PATTERN_LEN)
		return 0;

	for (i = 0; i < MAX_PATTERN_LEN; i++) {
		if (i >= path_len)
			break;
		idx = i & (MAX_PATH_LEN - 1);
		pi = (i + 1) & (MAX_PATTERN_LEN - 1);
		if (path[idx] != pat[pi])
			return 0;
	}
	return 1;
}

static __always_inline __u32 match_blocked_commands(const char *path, __u32 path_len)
{
	__u32 i;

	for (i = 0; i < MAX_CMD_RULES; i++) {
		__u32 idx = i;
		struct path_pattern_entry *e;

		e = bpf_map_lookup_elem(&blocked_command_patterns, &idx);
		if (!e || e->pattern_len == 0)
			continue;
		if (path_ends_with(path, path_len, e->pattern, e->pattern_len))
			return e->policy_id;
		if (path_is_basename(path, path_len, e->pattern, e->pattern_len))
			return e->policy_id;
	}
	return 0;
}

/* Prefix match with boundary: "/workspace" matches "/workspace" and
 * "/workspace/foo", not "/workspace-evil". Mask indices like path_ends_with. */
static __always_inline int path_starts_with_64(const char *path, __u32 path_len,
					      const char *pat, __u32 pat_len)
{
	__u32 i, idx, pi;

	if (pat_len == 0 || pat_len > MAX_PATTERN_LEN)
		return 0;
	if (path_len >= MAX_PATH_LEN || path_len < pat_len)
		return 0;

	for (i = 0; i < MAX_PATTERN_LEN; i++) {
		if (i >= pat_len)
			break;
		idx = i & (MAX_PATH_LEN - 1);
		pi = i & (MAX_PATTERN_LEN - 1);
		if (path[idx] != pat[pi])
			return 0;
	}
	if (path_len == pat_len)
		return 1;
	idx = pat_len & (MAX_PATH_LEN - 1);
	return path[idx] == '/';
}

static __always_inline int path_starts_with_256(const char *path, __u32 path_len,
					       const char *pat, __u32 pat_len)
{
	__u32 i, idx, pi;

	if (pat_len == 0 || pat_len > MAX_PATH_LEN)
		return 0;
	if (path_len >= MAX_PATH_LEN || path_len < pat_len)
		return 0;

	for (i = 0; i < MAX_PATH_LEN; i++) {
		if (i >= pat_len)
			break;
		idx = i & (MAX_PATH_LEN - 1);
		pi = i & (MAX_PATH_LEN - 1);
		if (path[idx] != pat[pi])
			return 0;
	}
	if (path_len == pat_len)
		return 1;
	idx = pat_len & (MAX_PATH_LEN - 1);
	return path[idx] == '/';
}

static __always_inline int path_in_workspace(const char *path, __u32 path_len)
{
	__u32 zero = 0, i;
	struct workspace_root_entry *w;
	struct prefix_entry *e;

	w = bpf_map_lookup_elem(&workspace_root, &zero);
	if (w && w->prefix_len &&
	    path_starts_with_256(path, path_len, w->prefix, w->prefix_len))
		return 1;

	for (i = 0; i < MAX_ALLOW_PREFIXES; i++) {
		__u32 idx = i;

		e = bpf_map_lookup_elem(&allowed_path_prefixes, &idx);
		if (!e || e->pattern_len == 0)
			continue;
		if (path_starts_with_64(path, path_len, e->pattern, e->pattern_len))
			return 1;
	}
	return 0;
}

static __always_inline __u32 workspace_policy_id(void)
{
	__u32 zero = 0;
	struct workspace_root_entry *w = bpf_map_lookup_elem(&workspace_root, &zero);

	return w ? w->policy_id : 0;
}

static __always_inline int deny_path(__u32 pid, __u32 policy_id, const char *path)
{
	struct violation_event *v = bpf_ringbuf_reserve(&violations, sizeof(*v), 0);

	if (v) {
		v->timestamp_ns = bpf_ktime_get_ns();
		v->pid = pid;
		v->policy_type = policy_id;
		bpf_get_current_comm(v->typed_comm, sizeof(v->typed_comm));
		__builtin_memset(v->canonical_path, 0, sizeof(v->canonical_path));
		__builtin_memset(v->detail, 0, sizeof(v->detail));
		if (path)
			bpf_probe_read_kernel_str(v->detail, sizeof(v->detail), path);
		bpf_ringbuf_submit(v, 0);
	}
	return -EPERM;
}

/* Parent-dir check for unlink/rename/create. Fail closed when confinement is on. */
static __always_inline int confine_path_struct(struct path *dirpath)
{
	__u32 tid, pid;
	__u32 zero = 0;
	char *path;
	long n;
	__u32 path_len;
	__u32 pol;

	if (current_nspids(&tid, &pid))
		return 0;
	if (!bpf_map_lookup_elem(&tracked_pids, &pid))
		return 0;
	if (!enforce_workspace)
		return 0;

	path = bpf_map_lookup_elem(&file_open_path, &zero);
	if (!path)
		return -EPERM;

	__builtin_memset(path, 0, MAX_PATH_LEN);
	n = bpf_d_path(dirpath, path, MAX_PATH_LEN);
	pol = workspace_policy_id();
	if (n <= 0 || n >= MAX_PATH_LEN)
		return deny_path(pid, pol, path);

	path_len = (__u32)n - 1;
	if (path_len >= MAX_PATH_LEN)
		path_len = MAX_PATH_LEN - 1;

	if (!path_in_workspace(path, path_len))
		return deny_path(pid, pol, path);
	return 0;
}

static __always_inline int path_contains_128_3char(const char *buf, char p1, char p2, char p3){
    #pragma unroll
    for (int i = 0; i < 125; i++){
        // Blindly scan everything. No breaking on null bytes!
        if (buf[i] == p1 && buf[i + 1] == p2 && buf[i + 2] == p3){
            return 1;
        }
    }
    return 0;
}


SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file){
	__u32 tid, pid;
	if (current_nspids(&tid, &pid))
		return 0;
	__u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	__u32 zero = 0;
	char *path;
	__u32 path_len;
	__u32 hit_policy = 0;
	int hit = 0;
	struct violation_event *v;
	long n;

	if (!tracked)
		return 0;

	path = bpf_map_lookup_elem(&file_open_path, &zero);
	if (!path) {
		if (enforce_workspace)
			return -EPERM;
		return 0;
	}

	__builtin_memset(path, 0, MAX_PATH_LEN);
	n = bpf_d_path(&file->f_path, path, MAX_PATH_LEN);
	if (n <= 0 || n >= MAX_PATH_LEN) {
		if (enforce_workspace)
			return deny_path(pid, workspace_policy_id(), path);
		return 0;
	}
	/* bpf_d_path returns length including trailing NUL */
	path_len = (__u32)n - 1;
	if (path_len >= MAX_PATH_LEN)
		path_len = MAX_PATH_LEN - 1;

	if (enforce_workspace && !path_in_workspace(path, path_len))
		return deny_path(pid, workspace_policy_id(), path);

	for (__u32 i = 0; i < MAX_PATH_RULES; i++) {
		__u32 idx = i;
		struct path_pattern_entry *e;
		int matched;

		e = bpf_map_lookup_elem(&blocked_path_patterns, &idx);
		if (!e || e->pattern_len == 0)
			continue;

		matched = path_ends_with(path, path_len, e->pattern, e->pattern_len);
		if (matched) {
			hit = 1;
			hit_policy = e->policy_id;
			break;
		}
	}

	if (!hit)
		return 0;

	v = bpf_ringbuf_reserve(&violations, sizeof(*v), 0);
	if (v) {
		v->timestamp_ns = bpf_ktime_get_ns();
		v->pid = pid;
		v->policy_type = hit_policy;
		bpf_get_current_comm(v->typed_comm, sizeof(v->typed_comm));
		__builtin_memset(v->canonical_path, 0, sizeof(v->canonical_path));
		__builtin_memset(v->detail, 0, sizeof(v->detail));
		bpf_probe_read_kernel_str(v->detail, sizeof(v->detail), path);
		bpf_ringbuf_submit(v, 0);
	}
	return -EPERM;
}

SEC("lsm/path_unlink")
int BPF_PROG(check_path_unlink, const struct path *dir, struct dentry *dentry)
{
	(void)dentry;
	return confine_path_struct((struct path *)dir);
}

SEC("lsm/path_rename")
int BPF_PROG(check_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	int err;

	(void)old_dentry;
	(void)new_dentry;
	(void)flags;

	err = confine_path_struct((struct path *)old_dir);
	if (err)
		return err;
	return confine_path_struct((struct path *)new_dir);
}

/* path_mknod is not sleepable: bpf_d_path is illegal. bpf_path_d_path is a
 * kfunc and is allowed on this hook when dir is the trusted LSM argument. */
SEC("lsm/path_mknod")
int BPF_PROG(check_path_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	__u32 tid, pid;
	__u32 zero = 0;
	char *path;
	long n;
	__u32 path_len;

	(void)dentry;
	(void)mode;
	(void)dev;

	if (current_nspids(&tid, &pid))
		return 0;
	if (!bpf_map_lookup_elem(&tracked_pids, &pid))
		return 0;
	if (!enforce_workspace)
		return 0;

	path = bpf_map_lookup_elem(&file_open_path, &zero);
	if (!path)
		return -EPERM;

	__builtin_memset(path, 0, MAX_PATH_LEN);
	n = bpf_path_d_path(dir, path, MAX_PATH_LEN);
	if (n <= 0 || n >= MAX_PATH_LEN)
		return deny_path(pid, workspace_policy_id(), path);

	path_len = (__u32)n - 1;
	if (path_len >= MAX_PATH_LEN)
		path_len = MAX_PATH_LEN - 1;

	if (!path_in_workspace(path, path_len))
		return deny_path(pid, workspace_policy_id(), path);
	return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(check_path_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	(void)dentry;
	(void)mode;
	return confine_path_struct((struct path *)dir);
}

SEC("lsm/path_symlink")
int BPF_PROG(check_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name)
{
	(void)dentry;
	(void)old_name;
	return confine_path_struct((struct path *)dir);
}

SEC("lsm/path_link")
int BPF_PROG(check_path_link, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry)
{
	(void)old_dentry;
	(void)new_dentry;
	/* bpf_d_path requires a trusted kernel path. A stack-built {mnt,dentry}
	 * for the source file is rejected (R1 type=fp). Only new_dir is usable. */
	return confine_path_struct((struct path *)new_dir);
}

SEC("lsm/path_rmdir")
int BPF_PROG(check_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	(void)dentry;
	return confine_path_struct((struct path *)dir);
}

static __always_inline int report_and_deny(__u32 pid, __u32 daddr_host, __u16 dport) {
    struct violation_event *v = bpf_ringbuf_reserve(&violations, sizeof(*v), 0);
    if (v) {
        v->timestamp_ns = bpf_ktime_get_ns();
        v->pid          = pid;
        v->policy_type  = network_policy_id;
        bpf_get_current_comm(v->typed_comm, sizeof(v->typed_comm));
        __builtin_memset(v->canonical_path, 0, sizeof(v->canonical_path));
        __builtin_memset(v->detail, 0, sizeof(v->detail));
        BPF_SNPRINTF(v->detail, sizeof(v->detail), "%pi4:%d", &daddr_host, dport);
        bpf_ringbuf_submit(v, 0);              
    }
    return enforce_network ? -EPERM : 0;
}

/*
SEC("lsm/socket_connect")
int BPF_PROG(check_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen){
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!tracked)
        return 0;

    if (address->sa_family != AF_INET)
        return 0;

    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    __u32 dest_ip = addr_in->sin_addr.s_addr;

    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);

    if (!allowed){
        struct violation_event *v = bpf_ringbuf_reserve(&violations, sizeof(*v), 0);
        if (v){
            v->timestamp_ns = bpf_ktime_get_ns();
            v->pid = pid;
            v->policy_type = network_policy_id;     // network 
            //Grab the process name
            bpf_get_current_comm(v->typed_comm, sizeof(v->typed_comm));
            __builtin_memset(v->detail, 0, sizeof(v->detail));
            // store the raw IP bytes for now; format in Go on the userspace side
            // char net_target[] = "Restricted External IP";
            //__builtin_memcpy(v->detail, net_target, sizeof(net_target));
            __builtin_memcpy(v->detail, &dest_ip, 4);
            bpf_ringbuf_submit(v, 0);
        }
        return -EPERM;
    }
    return 0;
}
*/

SEC("lsm/socket_connect")
int BPF_PROG(check_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen){
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;
    if(!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;
    __u16 family = address->sa_family;

    if (family == AF_UNIX) 
        return 0;
    if (family == AF_INET6)
        return report_and_deny(pid, 0, 0);   // No IPv6 path exists
    if (family != AF_INET)
        return 0;
    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    __u32 daddr = bpf_ntohl(sin->sin_addr.s_addr);
    __u16 dport = bpf_ntohs(sin->sin_port);

    if (daddr == proxy_addr_host && dport == proxy_port_host)
        return 0;

    if (allow_local_dns && dport == 53 && daddr == dns_addr_host)
        return 0;

    return report_and_deny(pid, sin->sin_addr.s_addr, dport);
}

//check_socket_create
//inet_sock_set_state

// connect() alone isn't enough - an unconnected UDP socket doing sendto()/sendmsg()
// never passes through security_socket_connect, and that's a working exfiltration
// channel (e.g. DNS tunneling) if left unguarded.
SEC("lsm/socket_sendmsg")
int BPF_PROG(check_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size){
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;
    // connected sockets carry no msg_name - vetted at connect()
    // Only unconnected sendto()/sendmsg() sets it
    void *name = BPF_CORE_READ(msg, msg_name);
    if (!name)
        return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_kernel(&sin, sizeof(sin), name);
    if (sin.sin_family != AF_INET)
        return sin.sin_family == AF_INET6 ? report_and_deny(pid, 0, 0) : 0;

    __u32 daddr = bpf_ntohl(sin.sin_addr.s_addr);
    __u16 dport = bpf_ntohs(sin.sin_port);

    if (daddr == proxy_addr_host && dport == proxy_port_host)
        return 0;
    if (allow_local_dns && dport == 53 && daddr == dns_addr_host)
        return 0;
    return report_and_deny(pid, sin.sin_addr.s_addr, dport);
}

// Belt-and-braces : deny raw sockets outright. Unpriviledged processes normally can't 
// get CAP_NET_RAW anyway, but a raw socket would otherwise bypass both hooks above -
// AF_PACKET operates below IP, and SOCK_RAW lets a process hand-craft packets that
// don't go through the normal connect()/sendmsg() path this policy inspects.
SEC("lsm/socket_create")
int BPF_PROG(check_socket_create, int family, int type, int protocol, int kern) {
    __u32 tid, pid;
    if (current_nspids(&tid, &pid))
        return 0;
    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return 0;

    int sock_type = type & 0xFF;   // mask off SOCK_CLOEXEC / SOCK_NONBLOCK flags
    if (family == AF_PACKET || sock_type == SOCK_RAW)
        return report_and_deny(pid, 0, 0);
    
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm){
	__u32 tid, pid;
	if (current_nspids(&tid, &pid))
		return 0;
	__u32 zero = 0;
	char *path;
	__u32 hit_policy = 0;
	long n;
	struct violation_event *v;
	const char *fname;

	if (!bpf_map_lookup_elem(&tracked_pids, &pid))
		return 0;

	path = bpf_map_lookup_elem(&exec_path, &zero);
	if (!path)
		return 0;

	__builtin_memset(path, 0, MAX_PATH_LEN);
	n = bpf_d_path(&bprm->file->f_path, path, MAX_PATH_LEN);
	if (n > 0) {
		__u32 path_len = (__u32)n - 1;
		if (path_len >= MAX_PATH_LEN)
			path_len = MAX_PATH_LEN - 1;
		hit_policy = match_blocked_commands(path, path_len);
	}

	if (!hit_policy) {
		fname = BPF_CORE_READ(bprm, filename);
		__builtin_memset(path, 0, MAX_PATH_LEN);
		n = bpf_probe_read_kernel_str(path, MAX_PATH_LEN, fname);
		if (n > 0) {
			__u32 path_len = (__u32)n - 1;
			if (path_len >= MAX_PATH_LEN)
				path_len = MAX_PATH_LEN - 1;
			hit_policy = match_blocked_commands(path, path_len);
		}
	}

	if (!hit_policy)
		return 0;

	v = bpf_ringbuf_reserve(&violations, sizeof(*v), 0);
	if (v) {
		v->timestamp_ns = bpf_ktime_get_ns();
		v->pid = pid;
		v->policy_type = hit_policy;
		bpf_get_current_comm(v->typed_comm, sizeof(v->typed_comm));
		__builtin_memset(v->canonical_path, 0, sizeof(v->canonical_path));
		__builtin_memset(v->detail, 0, sizeof(v->detail));
		bpf_probe_read_kernel_str(v->canonical_path, sizeof(v->canonical_path), path);
		bpf_probe_read_kernel_str(v->detail, sizeof(v->detail), path);
		bpf_ringbuf_submit(v, 0);
	}
	return -EPERM;
}