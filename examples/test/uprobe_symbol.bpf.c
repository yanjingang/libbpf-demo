/**
 * 通过使用 uprobe + use symbols offset（用户空间探针）在用户空间程序函数的入口和退出处放置钩子，实现对该用户态函数调用的跟踪
*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 通过 SEC 宏来定义 uprobe 探针（未在SEC中指定二进制路径和函数名称，则需要使用bpf_program__attach_uprobe进行指定参数附加）
SEC("uprobe")
int BPF_KPROBE(utest_add, int a, int b)
{
    bpf_printk("utest_add ENTRY: a = %d, b = %d", a, b);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(urettest_add, int ret)
{
    bpf_printk("utest_add EXIT: return = %d", ret);
    return 0;
}
