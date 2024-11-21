#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM  1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Key: Inode number
    __type(value, __u32); // Value: Does not really matter but fill for 1.
    __uint(max_entries, 1024);  
} restricted_inodes_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // Key: Restricted pid number
    __type(value, __u32); // Value: Parent pid number.
    __uint(max_entries, 30);  
} restricted_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Key: Inode number that have been access and rejected
    __type(value, __u32); // Value: Does not really matter but fill for 1.
    __uint(max_entries, 1024);  
} inode_access_map SEC(".maps");

SEC("lsm/inode_permission")
int BPF_PROG(lsm_bpf, struct inode *inode, int mask)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *is_restricted_pid = bpf_map_lookup_elem(&restricted_pid_map, &pid);
    if (is_restricted_pid == NULL) {
        return 0;
    }
    __u64 target_inode = inode->i_ino;
    __u32 *is_restricted_inode = bpf_map_lookup_elem(&restricted_inodes_map, &target_inode);
    if (is_restricted_inode) {
        __u32 placeholder = 1;
        bpf_map_update_elem(&inode_access_map, &target_inode, &placeholder, BPF_ANY);
        return -EPERM;
    }
    return 0;
    
}

SEC("tp/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    // Retrieve the parent and child PIDs from the tracepoint context
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;
    
    __u32 *is_restricted_pid = bpf_map_lookup_elem(&restricted_pid_map, &parent_pid);
    if (is_restricted_pid != NULL) {
        bpf_map_update_elem(&restricted_pid_map, &child_pid, &parent_pid, BPF_ANY);
    }

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	pid_t pid, tid;
	u64 id;

    __u32 pid32 = (__u32) pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	if (pid != tid)
		return 0;
    
    __u32 *is_restricted_pid = bpf_map_lookup_elem(&restricted_pid_map, &pid32);
    if (is_restricted_pid != NULL) {
        bpf_map_delete_elem(&restricted_pid_map, &pid32);
    }

	return 0;
}
