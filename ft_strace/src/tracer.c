#define _GNU_SOURCE
#include "../inc/ft_strace.h"
#include <sys/time.h>
#include <time.h>
#include <ctype.h>

t_syscall_stats stats_64[MAX_SYSCALL_64 + 1];
t_syscall_stats stats_32[MAX_SYSCALL_32 + 1];

static int in_syscall = 0;
static struct timeval start_tv;

void handle_signal_forward(t_strace *ctx, int status) {
    (void)ctx; (void)status; // Handled in trace_loop directly
}

int is_32bit_process(struct user_regs_struct *regs) {
    return (regs->cs == 0x23);
}

// Print string from remote process.
// len: -1 if null-terminated, otherwise max length to read/print
void print_remote_string(t_strace *ctx, unsigned long addr, long len) {
    if (addr == 0) {
        fprintf(stderr, "NULL");
        return;
    }

    char buf[1024];
    long read_limit = (len == -1 || len > 32) ? 64 : len + 1; // Read a bit more to checks
    if (read_limit > (long)sizeof(buf)) read_limit = sizeof(buf);

    struct iovec local = { buf, read_limit };
    struct iovec remote = { (void*)addr, read_limit };

    ssize_t nread = process_vm_readv(ctx->pid, &local, 1, &remote, 1, 0);
    if (nread <= 0) {
        fprintf(stderr, "%p", (void*)addr);
        return;
    }

    // Determine actual string length to print
    int str_len = 0;
    if (len == -1) {
        // Null terminated search
        while (str_len < nread && buf[str_len] != 0) str_len++;
    } else {
        str_len = (len < nread) ? len : nread;
    }

    fprintf(stderr, "\"");
    int print_limit = (str_len > 32) ? 32 : str_len;
    
    for (int i = 0; i < print_limit; i++) {
        unsigned char c = buf[i];
        if (c == '\n') fprintf(stderr, "\\n");
        else if (c == '\r') fprintf(stderr, "\\r");
        else if (c == '\t') fprintf(stderr, "\\t");
        else if (c == '"') fprintf(stderr, "\\\"");
        else if (c == '\\') fprintf(stderr, "\\\\");
        else if (isprint(c)) fputc(c, stderr);
        else fprintf(stderr, "\\x%02x", c);
    }
    
    if (str_len > 32 || (len == -1 && str_len == nread && buf[nread-1] != 0)) {
        fprintf(stderr, "...");
    }
    fprintf(stderr, "\"");
}

void print_args(t_strace *ctx, struct user_regs_struct *regs, int is_32, long syscall_nr) {
    long args[6];
    if (is_32) {
        args[0] = regs->rbx;
        args[1] = regs->rcx;
        args[2] = regs->rdx;
        args[3] = regs->rsi;
        args[4] = regs->rdi;
        args[5] = regs->rbp;
    } else {
        args[0] = regs->rdi;
        args[1] = regs->rsi;
        args[2] = regs->rdx;
        args[3] = regs->r10;
        args[4] = regs->r8;
        args[5] = regs->r9;
    }
    
    const char *name = get_syscall_name(syscall_nr, is_32);
    
    // Custom formatters for common syscalls
    if (!strcmp(name, "write") || !strcmp(name, "read")) {
        // (fd, buf, count)
        fprintf(stderr, "%ld, ", args[0]);
        if (!strcmp(name, "write"))
            print_remote_string(ctx, args[1], args[2]); // Print buffer content for write
        else
             fprintf(stderr, "%p", (void*)args[1]); // For read, buffer is output, print address
        fprintf(stderr, ", %ld", args[2]);
        return;
    }
    
    if (!strcmp(name, "open") || !strcmp(name, "openat") || !strcmp(name, "access") || !strcmp(name, "stat") || !strcmp(name, "lstat")) {
        int idx = 0;
        if (!strcmp(name, "openat")) {
            if ((int)args[0] == -100) fprintf(stderr, "AT_FDCWD, ");
            else fprintf(stderr, "%ld, ", args[0]);
            idx = 1;
        }
        print_remote_string(ctx, args[idx], -1); // path
        // Print remaining args
        for (int i = idx + 1; i < 6; i++) {
             // For open/openat flags, printing hex is fine.
             // We could be fancy but let's stick to hex
             // Avoid printing 0s for later args?
             if (args[i] == 0 && i > idx + 2) break; // heuristic stop
             fprintf(stderr, ", 0x%lx", args[i]);
        }
        return;
    }
    
    if (!strcmp(name, "execve")) {
        // (filename, argv, envp)
        print_remote_string(ctx, args[0], -1);
        fprintf(stderr, ", %p, %p", (void*)args[1], (void*)args[2]);
        // Ideally we iterate argv, but complex.
        return;
    }

    // Default hex print
    for (int i = 0; i < 6; i++) {
        fprintf(stderr, "%s0x%lx%s", i == 0 ? "" : ", ", args[i], i == 5 ? "" : "");
    }
}

int trace_loop(t_strace *ctx) {
    int status;
    struct user_regs_struct regs;
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(struct user_regs_struct);

    sigset_t empty, blocked;
    sigemptyset(&empty);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGPIPE);
    sigaddset(&blocked, SIGTERM);

    while (1) {
        sigprocmask(SIG_SETMASK, &empty, NULL);
        wait4(ctx->pid, &status, 0, NULL);
        sigprocmask(SIG_BLOCK, &blocked, NULL);

        if (WIFEXITED(status)) {
            if (!ctx->mode_c)
                fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
            break;
        }
        if (WIFSIGNALED(status)) {
            if (!ctx->mode_c)
                fprintf(stderr, "+++ killed by SIG%d +++\n", WTERMSIG(status));
            break;
        }
        
        if (WIFSTOPPED(status)) {
            int signal_to_deliver = 0;
            int sig = WSTOPSIG(status);

            if (sig == (SIGTRAP | 0x80)) {
                // Syscall stop
                ptrace(PTRACE_GETREGSET, ctx->pid, NT_PRSTATUS, &iov);
                
                ctx->is_32bit = is_32bit_process(&regs);
                long syscall_nr = ctx->is_32bit ? regs.orig_rax : regs.orig_rax;
                
                if (!in_syscall) {
                    // ENTRY
                    in_syscall = 1;
                    
                    if (ctx->mode_c) {
                        gettimeofday(&start_tv, NULL);
                        if (ctx->is_32bit) {
                            if (syscall_nr <= MAX_SYSCALL_32) stats_32[syscall_nr].calls++;
                        } else {
                            if (syscall_nr <= MAX_SYSCALL_64) stats_64[syscall_nr].calls++;
                        }
                    } else {
                        const char *name = get_syscall_name(syscall_nr, ctx->is_32bit);
                        fprintf(stderr, "%s(", name);
                        print_args(ctx, &regs, ctx->is_32bit, syscall_nr);
                        fprintf(stderr, ") ");
                    }
                } else {
                    // EXIT
                    in_syscall = 0;
                    
                    if (ctx->mode_c) {
                        struct timeval end_tv;
                        gettimeofday(&end_tv, NULL);
                        double elapsed = (end_tv.tv_sec - start_tv.tv_sec) + 
                                         (end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;
                         if (ctx->is_32bit) {
                            if (syscall_nr <= MAX_SYSCALL_32) stats_32[syscall_nr].time += elapsed;
                        } else {
                            if (syscall_nr <= MAX_SYSCALL_64) stats_64[syscall_nr].time += elapsed;
                        }
                        
                        long ret_val = regs.rax; 
                        if ((long)ret_val < 0) {
                              if (ctx->is_32bit) {
                                if (syscall_nr <= MAX_SYSCALL_32) stats_32[syscall_nr].errors++;
                            } else {
                                if (syscall_nr <= MAX_SYSCALL_64) stats_64[syscall_nr].errors++;
                            }
                        }
                        
                    } else {
                        long ret = regs.rax;
                        fprintf(stderr, "= %ld\n", ret);
                    }
                }
            } else {
                 if (sig == SIGTRAP) {
                     int event = (status >> 16) & 0xffff;
                     if (event == PTRACE_EVENT_EXEC) {
                         if (!ctx->mode_c) {
                             // PTRACE_EVENT_EXEC happens triggers before return from execve
                             // but we might miss the syscall ENTRY because it was started before Seizing?
                             // No, execve triggers normal syscall entry/exit if we trace it.
                             // But PTRACE_EVENT_EXEC is an extra stop.
                             // Just ignore it.
                         }
                     } else {
                         // Weird SIGTRAP
                     }
                } else {
                    if (!ctx->mode_c) {
                        siginfo_t si;
                        ptrace(PTRACE_GETSIGINFO, ctx->pid, 0, &si);
                        // Make sure we output valid signal info
                        fprintf(stderr, "--- %s {si_signo=%d, si_code=%d, si_pid=%d, si_uid=%d} ---\n", 
                            strsignal(sig), si.si_signo, si.si_code, si.si_pid, si.si_uid);
                    }
                    signal_to_deliver = sig;
                }
            }
            ptrace(PTRACE_SYSCALL, ctx->pid, 0, signal_to_deliver);
        }
    }
    return 0;
}
