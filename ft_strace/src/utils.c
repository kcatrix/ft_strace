#define _GNU_SOURCE
#include "../inc/ft_strace.h"
#include <fcntl.h>

int is_elf(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    
    unsigned char buf[4];
    if (read(fd, buf, 4) != 4) {
        close(fd);
        return 0;
    }
    close(fd);
    
    if (buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')
        return 1;
    return 0;
}

void error_exit(const char *msg) {
    perror(msg);
    exit(1);
}

char *find_binary(char *cmd, char **env) {
    if (strchr(cmd, '/')) {
        if (access(cmd, X_OK) == 0)
            return strdup(cmd);
        return NULL;
    }

    char *path_var = NULL;
    for (int i = 0; env[i]; i++) {
        if (strncmp(env[i], "PATH=", 5) == 0) {
            path_var = env[i] + 5;
            break;
        }
    }

    if (!path_var) return NULL;

    char *path_dup = strdup(path_var);
    char *dir = strtok(path_dup, ":");
    static char full_path[4096];

    while (dir) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, cmd);
        if (access(full_path, X_OK) == 0) {
            free(path_dup);
            return strdup(full_path);
        }
        dir = strtok(NULL, ":");
    }
    free(path_dup);
    return NULL;
}

const char *get_syscall_name(int nr, int is_32bit) {
    if (is_32bit) {
        if (nr >= 0 && nr <= MAX_SYSCALL_32)
            return syscall_names_32[nr];
    } else {
        if (nr >= 0 && nr <= MAX_SYSCALL_64)
            return syscall_names_64[nr];
    }
    return "unknown";
}
