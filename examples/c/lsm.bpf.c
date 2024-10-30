#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>
char LICENSE[] SEC("license") = "GPL";

#define EPERM  1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);                // Key: PID of the process
    __type(value, char[PATH_MAX]);   // Value: Restricted directory path
    __uint(max_entries, 30);         //
} pid_directory_map SEC(".maps");

SEC("lsm/inode_permission")
int BPF_PROG(lsm_bpf, struct inode *inode, int mask)
{
    int pid = bpf_get_current_pid_tgid() >> 32; 
    char *restricted_dir;

    restricted_dir = bpf_map_lookup_elem(&pid_directory_map, &pid);
    if (!restricted_dir) {
        return 0; 
    }
    char path[PATH_MAX];
    if (bpf_d_path(&inode->i_path, path, sizeof(path)) < 0) {
        return -EPERM;
    }
    if (strncmp(path, restricted_dir, strlen(restricted_dir)) != 0) {
        return -EPERM;  
    }
}
