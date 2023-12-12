#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_sys_openat2")	// 使用SEC宏把下方函数插入到openant系统调用入口执行
int BPF_KPROBE(do_sys_openat2, int dfd, struct filename *name)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("Hello eBPF! kprobe entry pid = %d\n", pid);
	return 0;
}


const pid_t pid_filter = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid_filter && pid != pid_filter)
		return 0;
	bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
	return 0;
}