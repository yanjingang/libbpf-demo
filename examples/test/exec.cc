/**
 * ebpf 用户空间程序(loader、read perf buffer)
*/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "exec.skel.h"
#include "exec.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

// Control-C process
static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

// ring buffer data process
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = reinterpret_cast<struct event *>(data);
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (e->is_exit) {
        printf("%s %-5s %d %d %s %d %llums\n", ts, "EXIT", e->pid, e->uid, e->cmd, e->retval, e->ns / 1000000);
    } else {
        printf("%s %-5s %d %d %s\n", ts, "EXEC", e->pid, e->uid, e->cmd);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct exec_bpf *skel;
    int err;
    struct ring_buffer *rb = NULL;

    /* 设置libbpf错误和调试信息回调 */
    libbpf_set_print(libbpf_print_fn);

    /* Control-C 停止信号 */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    /* 加载并验证 exec.bpf.c 应用程序 */
    skel = exec_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 附加 exec.bpf.c 程序到跟踪点 */
    err = exec_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        exec_bpf__destroy(skel);
        return -err;
    }
    // printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n");

    /* 设置环形缓冲区轮询 */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        exec_bpf__destroy(skel);
        return -err;
    }

    /* 处理收到的内核数据 */
    printf("%-8s %-8s %-7s %-7s %-16s %-8s %-8s\n", "TIME", "TYPE", "PID", "UID", "CMD", "RET", "DURATION");
    while (!exiting) {
        // 轮询内核数据
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {    /* Ctrl-C will cause -EINTR */
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
}
