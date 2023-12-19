/**
 * 通过使用 uprobe + use symbols offset（用户空间探针）在用户空间程序函数的入口和退出处放置钩子，实现对该用户态函数调用的跟踪
*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe_symbol.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义ring buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256 KB
} rb SEC(".maps");

// 通过 SEC 宏来定义 uprobe 探针（未在SEC中指定二进制路径和函数名称，则需要使用bpf_program__attach_uprobe进行指定参数附加）
SEC("uprobe")
int BPF_KPROBE(utest_add, int a, int b)
{
    // 使用bpf_printk函数在内核日志中打印
    bpf_printk("utest_add ENTRY: a = %d, b = %d", a, b);

    pid_t pid = (u32)bpf_get_current_pid_tgid();
    struct event *e;

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->pid = pid;
    e->a = a;
    e->b = b;
    e->exit_event = false;
    e->ns = bpf_ktime_get_ns();
    // 提交到ringbuf用户空间进行后处理
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(urettest_add, int ret)
{
    // 使用bpf_printk函数在内核日志中打印
    bpf_printk("utest_add EXIT: return = %d", ret);

    pid_t pid = (u32)bpf_get_current_pid_tgid();
    struct event *e;

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->pid = pid;
    e->exit_event = true;
    e->exit_ret = ret;
    e->ns = bpf_ktime_get_ns();
    // 提交ringbuf样本空间
    bpf_ringbuf_submit(e, 0);

    return 0;
}
