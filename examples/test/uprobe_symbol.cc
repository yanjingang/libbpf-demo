/**
 * ebpf 用户空间程序(loader)
*/
#include <errno.h>
#include <fstream>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe_symbol.skel.h"
#include "proto/symbol.pb.h"
#include "utils.h"

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
    if(argc < 2){
        std::cout << "usage: ./uprobe_symbol <pid>" << std::endl;
        return 0;
    }
    struct uprobe_symbol_bpf *skel;
    int err, i;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    std::string symbol_dump_file = "./symbols-utest_class.dump";
    std::string func_name = "test::UTest::utest_add(int, int)";
    std::string binary_path = "";   //home/work/project/libbpf-demo/examples/test/build/utest_class
    char bin_path[PATH_MAX];
    pid_t pid = atoi(argv[1]);

    // 通过pid获取可执行文件路径
	if (pid){
        if(get_binary_file_by_pid(pid, bin_path, sizeof(bin_path)) == 0){
            binary_path = bin_path;
            std::cout << "binary_path: " << binary_path << std::endl;
        }
		// get_pid_lib_path(pid, binary, path, path_sz);
    }

    // 加载symbols.dump文件
    std::ifstream is(symbol_dump_file, std::ios::binary);
    auto symbol = new Symbol();
    symbol->ParseFromIstream(&is);
    is.close();
    auto symbolMap = symbol->symbols();

    // 获取函数对应符号表的offset
    uint64_t func_offset = 0;
    func_offset = symbolMap[func_name];
    std::cout << "func_offset: [" << func_offset << "] " << func_name << std::endl;
    if (!func_offset) {
        std::cout << "failed to find symbol!" << std::endl;
        return 0;
    }

    /* 设置libbpf错误和调试信息回调 */
    libbpf_set_print(libbpf_print_fn);

    /* 加载并验证 kprobe.bpf.c 应用程序 */
    skel = uprobe_symbol_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 附加跟踪点处理 */
    // uprobe_opts.func_name = "_Z9utest_addii";
    uprobe_opts.retprobe = false;
    /* uprobe 期望要附加的函数的相对偏移量。
     *   如果我们提供函数名称，libbpf 会自动为我们找到偏移量。
     *   如果未指定函数名称，libbpf 将尝试使用函数偏移量代替。
     */
    skel->links.utest_add = bpf_program__attach_uprobe_opts(
        skel->progs.utest_add,
        -1,    // uprobe 的进程 ID，0 表示自身（自己的进程），-1 表示所有进程
        binary_path.c_str(),
        func_offset,    // offset for function
        &uprobe_opts);
    if (!skel->links.utest_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        uprobe_symbol_bpf__destroy(skel);
        return -err;
    }

    /* 将 uretprobe 附加到使用相同二进制可执行文件的任何现有或未来进程 */
    // uprobe_opts.func_name = "_Z9utest_addii";
    uprobe_opts.retprobe = true;
    skel->links.urettest_add = bpf_program__attach_uprobe_opts(
        skel->progs.urettest_add, 
        -1,    // uprobe 的进程 ID，0 表示自身（自己的进程），-1 表示所有进程
        binary_path.c_str(),
        func_offset,    // offset for function
        &uprobe_opts);
    if (!skel->links.urettest_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        uprobe_symbol_bpf__destroy(skel);
        return -err;
    }


    /* Control-C 停止信号 */
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        uprobe_symbol_bpf__destroy(skel);
        return -err;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }

}
