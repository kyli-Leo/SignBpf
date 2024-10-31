#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";

#define EPERM  1

const volatile __u32 restricted_pid;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Key: Inode number
    __type(value, __u32); // Value: Does not really matter but fill for 1.
    __uint(max_entries, 1024);  
} restricted_inodes_map SEC(".maps");

SEC("lsm/inode_permission")
int BPF_PROG(lsm_bpf, struct inode *inode, int mask)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32; 
    if (restricted_pid != pid) {
        return 0;
    }
    __u64 target_inode = inode->i_ino;
    __u32 *is_restricted = bpf_map_lookup_elem(&restricted_inodes_map, &target_inode);
    if (is_restricted) {
        return -EPERM;
    }
    return 0;
    
}
