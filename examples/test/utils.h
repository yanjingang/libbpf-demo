/**
 * utils
*/
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <gelf.h>

int get_binary_file_by_pid(pid_t pid, char *path, size_t path_sz) {
	ssize_t ret = 0;
	char proc_pid_exe[32];

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	        >= (int)sizeof(proc_pid_exe)) {
		std::cout << "snprintf /proc/PID/exe failed" << std::endl;
		return -1;
	}
	ret = readlink(proc_pid_exe, path, path_sz);
	if (ret < 0) {
		std::cout << "No such pid " << pid << std::endl;
		return -1;
	}
	if ((unsigned int)ret >= path_sz) {
		std::cout << "readlink truncation" << std::endl;
		return -1;
	}
	path[ret] = '\0';

	return 0;
}

int get_pid_lib_path(pid_t pid, const char *lib, char *path, size_t path_sz) {
	FILE *maps = NULL;
	char *p = NULL;
    char proc_pid_maps[32];
	char line_buf[1024];
	char path_buf[1024];

	if (snprintf(proc_pid_maps, sizeof(proc_pid_maps), "/proc/%d/maps", pid)
	        >= (int)sizeof(proc_pid_maps)) {
		std::cout << "snprintf /proc/PID/maps failed" << std::endl;
		return -1;
	}
	maps = fopen(proc_pid_maps, "r");
	if (!maps) {
		std::cout << "No such pid " << pid << std::endl;
		return -1;
	}
	while (fgets(line_buf, sizeof(line_buf), maps)) {
		if (sscanf(line_buf, "%*x-%*x %*s %*x %*s %*u %s", path_buf) != 1)
			continue;
		/* e.g. /usr/lib/x86_64-linux-gnu/libc-2.31.so */
		p = strrchr(path_buf, '/');
		if (!p)
			continue;
		if (strncmp(p, "/lib", 4))
			continue;
		p += 4;
		if (strncmp(lib, p, strlen(lib)))
			continue;
		p += strlen(lib);
		/* libraries can have - or . after the name */
		if (*p != '.' && *p != '-')
			continue;
		if (strnlen(path_buf, 1024) >= path_sz) {
			std::cout << "path size too small" << std::endl;
			return -1;
		}
		strcpy(path, path_buf);
		fclose(maps);
		return 0;
	}

	std::cout << "Cannot find library " << lib << std::endl;
	fclose(maps);
	return -1;
}
