/**
 * ebpf 用户空间程序(loader)
*/
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
// #include "proto/symbol.pb.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;
static void sig_int(int signo)
{
    stop = 1;
}

int main(int argc, char **argv)
{
    struct uprobe_bpf *skel;
    int err, i;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);


    // load symbols from file
    // std::ifstream is("./symbols.dump", std::ios::binary);
    // symbol = new Symbol();
    // symbol->ParseFromIstream(&is);
    // is.close();
    // symbolMap = symbol->symbols();


    /* 设置libbpf错误和调试信息回调 */
    libbpf_set_print(libbpf_print_fn);

    /* 加载并验证 kprobe.bpf.c 应用程序 */
    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 附加跟踪点处理 */
    uprobe_opts.func_name = "_Z9utest_addii";
    uprobe_opts.retprobe = false;
    /* uprobe 期望要附加的函数的相对偏移量。
     *   如果我们提供函数名称，libbpf 会自动为我们找到偏移量。
     *   如果未指定函数名称，libbpf 将尝试使用函数偏移量代替。
     */
    skel->links.utest_add = bpf_program__attach_uprobe_opts(
        skel->progs.utest_add,
        -1,    // uprobe 的进程 ID，0 表示自身（自己的进程），-1 表示所有进程
        "/home/work/project/libbpf-demo/examples/test/utest/build/utest",
        0,    // offset for function
        &uprobe_opts);
    if (!skel->links.utest_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        uprobe_bpf__destroy(skel);
        return -err;
    }

    /* 将 uretprobe 附加到使用相同二进制可执行文件的任何现有或未来进程 */
    uprobe_opts.func_name = "_Z9utest_addii";
    uprobe_opts.retprobe = true;
    skel->links.urettest_add = bpf_program__attach_uprobe_opts(
        skel->progs.urettest_add, 
        -1,    // uprobe 的进程 ID，0 表示自身（自己的进程），-1 表示所有进程
        "/home/work/project/libbpf-demo/examples/test/utest/build/utest",
        0,    // offset for function
        &uprobe_opts);
    if (!skel->links.urettest_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        uprobe_bpf__destroy(skel);
        return -err;
    }

    /* 让libbpf为 utest_sub/urettest_sub 执行自动附加
     *     注意：此方式需要在uprobe.bpf.c的SEC中提供路径和符号信息
     */
    err = uprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
        uprobe_bpf__destroy(skel);
        return -err;
    }

    /* Control-C 停止信号 */
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        uprobe_bpf__destroy(skel);
        return -err;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }

}
