#ifndef __EXEC_H
#define __EXEC_H

#define EXEC_CMD_LEN 128

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char cmd[EXEC_CMD_LEN];
    unsigned long long ns;
};

#endif /* __EXEC_H */