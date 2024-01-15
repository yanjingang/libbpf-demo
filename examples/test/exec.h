#ifndef __EXEC_H
#define __EXEC_H

#define EXEC_CMD_LEN 127
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char cmd[EXEC_CMD_LEN];
    char filename[MAX_FILENAME_LEN];
    unsigned long long ns;
};

#endif /* __EXEC_H */