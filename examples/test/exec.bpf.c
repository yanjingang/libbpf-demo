/**
 * 捕获 Linux 内核中进程执行的事件
*/
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exec.h"

// 定义ring buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256 KB
} rb SEC(".maps");


// 捕获进程执行事件，使用 ring buffer 向用户态打印输出
SEC("tracepoint/syscalls/sys_enter_execve")
int snoop_process_start(struct trace_event_raw_sys_enter* ctx)
{
    u64 id;
    pid_t pid;
    struct event *e;
    struct task_struct *task;

    // 获取当前进程的用户ID
    uid_t uid = (u32)bpf_get_current_uid_gid();
    // 获取当前进程ID
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    // 获取当前进程的task_struct结构体
    task = (struct task_struct*)bpf_get_current_task();
    // 读取进程名称
    char *cmd = (char *) BPF_CORE_READ(ctx, args[0]);

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->pid = pid;
    e->uid = uid;
    e->ppid = BPF_CORE_READ(task, real_parent, pid);
    bpf_probe_read_str(&e->cmd, EXEC_CMD_LEN, cmd);
    e->ns = bpf_ktime_get_ns();
    // 提交到ringbuf用户空间进行后处理
    bpf_ringbuf_submit(e, 0);

    // 使用bpf_printk函数在内核日志中打印 PID 和文件名
    // bpf_printk("TRACEPOINT EXEC pid = %d, uid = %d, cmd = %s\n", pid, uid, e->cmd);
    return 0;
}

// 监控进程退出事件，使用 ring buffer 向用户态打印输出
SEC("tp/sched/sched_process_exit")
int snoop_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;

    // 获取当前进程的用户ID
    uid_t uid = (u32)bpf_get_current_uid_gid();
    // 获取当前进程/线程ID
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;
    // 获取当前进程的task_struct结构体
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    // 预订一个ringbuf样本空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    // 设置数据
    e->ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->uid = uid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->is_exit = true;  //(BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->cmd, sizeof(e->cmd));
    // 提交到ringbuf用户空间进行后处理
    bpf_ringbuf_submit(e, 0);

    // 使用bpf_printk函数在内核日志中打印 PID 和文件名
    // bpf_printk("TRACEPOINT EXIT pid = %d, uid = %d, cmd = %s\n", pid, uid, e->cmd);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";