#ifndef __KPROBE_H
#define __KPROBE_H

#define MAX_FILENAME_LEN 256

struct event {
    int pid;
    char filename[MAX_FILENAME_LEN];
    bool exit_event;
    int exit_code;
    unsigned long long ns;
};

#endif