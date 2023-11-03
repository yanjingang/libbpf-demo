#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2, int dfd, struct filename *name)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("Hello eBPF! kprobe entry pid = %d\n", pid);
	return 0;
}
