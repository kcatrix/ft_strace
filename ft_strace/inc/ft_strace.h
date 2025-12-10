#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/uio.h>
#include <elf.h>
#include "syscall_table.h"

// Colors
#define RESET "\033[0m"
#define CYAN "\033[36m"

typedef struct s_strace {
    pid_t pid;
    int mode_c; // Counter mode
    char *bin_path;
    char **args;
    char **env;
    int is_32bit;
} t_strace;

typedef struct s_syscall_stats {
    long calls;
    long errors;
    double time; // In seconds, though we might just use clock ticks or similar if simple
} t_syscall_stats;

extern t_syscall_stats stats_64[];
extern t_syscall_stats stats_32[];

void error_exit(const char *msg);
char *find_binary(char *cmd, char **env);
int is_elf(const char *path);
void handle_signals(void);
void init_signals_child(void);

int trace_loop(t_strace *ctx);
void print_syscall(t_strace *ctx, struct user_regs_struct *regs, long syscall_nr);
void print_syscall_result(t_strace *ctx, struct user_regs_struct *regs, long ret);
const char *get_syscall_name(int nr, int is_32bit);

#endif
