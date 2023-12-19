#ifndef __KPROBE_H
#define __KPROBE_H

struct event {
    int pid;
    int a;
    int b;
    bool exit_event;
    int exit_ret;
    unsigned long long ns;
};

#endif