/**
 * 通过使用 kprobe（内核探针）在do_unlinkat函数的入口和退出处放置钩子，实现对该系统调用的跟踪
*/
#include <string.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

// 定义许可证，以允许程序在内核中运行
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义ring buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256 KB
} rb SEC(".maps");


// 定义一个名为do_unlinkat的 kprobe，当进入do_unlinkat函数时，它会被触发
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)  // 该函数接受两个参数：dfd（文件描述符）和name（文件名结构体指针）
{
    pid_t pid;
    const char *filename;
    struct event *e;

    // 获取当前进程的 PID（进程标识符）
    pid = bpf_get_current_pid_tgid() >> 32;
    // 读取文件名
    filename = BPF_CORE_READ(name, name);
    // 使用bpf_printk函数在内核日志中打印 PID 和文件名
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->pid = pid;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)filename);
	e->exit_event = false;
    e->ns = bpf_ktime_get_ns();
    // 提交到ringbuf用户空间进行后处理
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// 定义一个名为do_unlinkat_exit的 kretprobe，当从do_unlinkat函数退出时，它会被触发
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)   // 捕获函数的返回值（ret）
{
    pid_t pid;
    struct event *e;

    // 获取当前进程的 PID（进程标识符）
    pid = bpf_get_current_pid_tgid() >> 32;
    // 使用bpf_printk函数在内核日志中打印 PID 和返回值
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->pid = pid;
	e->exit_event = true;
    e->exit_code = ret;
    e->ns = bpf_ktime_get_ns();
    // 提交ringbuf样本空间
    bpf_ringbuf_submit(e, 0);

    return 0;
}