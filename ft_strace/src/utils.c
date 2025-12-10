#include "../inc/ft_strace.h"

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
