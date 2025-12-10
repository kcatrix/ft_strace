#include "../inc/ft_strace.h"

void print_usage(void) {
    fprintf(stderr, "Usage: ft_strace [-c] <command> [args...]\n");
    exit(1);
}

void print_stats(t_strace *ctx) {
    // Print stats like strace -c
    // % time     seconds  usecs/call     calls    errors syscall
    fprintf(stderr, "%6s %11s %11s %9s %9s %s\n", 
            "% time", "seconds", "usecs/call", "calls", "errors", "syscall");
    fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
    
    // Combine both 32 and 64 stats logic or just print valid ones
    // We iterate calling table.
    
    double total_time = 0;
    long total_calls = 0;
    long total_errors = 0;

    int max_s = ctx->is_32bit ? MAX_SYSCALL_32 : MAX_SYSCALL_64;
    t_syscall_stats *stats = ctx->is_32bit ? stats_32 : stats_64;

    for (int i = 0; i <= max_s; i++) {
        if (stats[i].calls > 0) {
            total_time += stats[i].time;
            total_calls += stats[i].calls;
            total_errors += stats[i].errors;
        }
    }

    for (int i = 0; i <= max_s; i++) {
        if (stats[i].calls > 0) {
            double percent = (total_time > 0) ? (stats[i].time * 100.0 / total_time) : 0.0;
            double usecs_call = (stats[i].time * 1000000.0) / stats[i].calls;
            const char *name = get_syscall_name(i, ctx->is_32bit);
            
            fprintf(stderr, "%6.2f %11.6f %11.0f %9ld %9ld %s\n",
                    percent, stats[i].time, usecs_call, stats[i].calls, stats[i].errors, name);
        }
    }
    fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(stderr, "%6.2f %11.6f %11.0f %9ld %9ld total\n", 
            100.00, total_time, 0.0, total_calls, total_errors);
}

int main(int argc, char **argv, char **envp) {
    if (argc < 2) print_usage();

    t_strace ctx = {0};
    ctx.env = envp;

    int arg_idx = 1;
    if (strcmp(argv[1], "-c") == 0) {
        if (argc < 3) print_usage();
        ctx.mode_c = 1;
        arg_idx++;
    }

    // Resolve path
    ctx.bin_path = find_binary(argv[arg_idx], envp);
    if (!ctx.bin_path) {
        fprintf(stderr, "ft_strace: command not found: %s\n", argv[arg_idx]);
        return 1;
    }

    if (!is_elf(ctx.bin_path)) {
       fprintf(stderr, "ft_strace: file format not recognized: %s\n", ctx.bin_path);
       free(ctx.bin_path);
       return 1; 
    }
    
    // Setup child args (starting from command)
    ctx.args = &argv[arg_idx];

    pid_t pid = fork();
    if (pid < 0) error_exit("fork");

    if (pid == 0) {
        // Child
        kill(getpid(), SIGSTOP); // Pause so parent can seize
        execve(ctx.bin_path, ctx.args, ctx.env);
        // If execve fails
        perror("execve");
        exit(1);
    } else {
        // Parent
        ctx.pid = pid;
        int status;
        waitpid(pid, &status, WSTOPPED);
        
        // Setup seizer options
        // PTRACE_O_TRACESYSGOOD: distinctive syscall stops
        // PTRACE_O_TRACEEXEC: stop on exec
        // PTRACE_O_EXITKILL: kill child if tracer exits
        unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
        
        if (ptrace(PTRACE_SEIZE, pid, 0, options) < 0) {
             perror("ptrace seize");
             kill(pid, SIGKILL);
             exit(1);
        }

        // Resume child (it was stopped by SIGSTOP)
        // We use PTRACE_SYSCALL so next stop is syscall entry/exit
        // Note: The child is stopped by SIGSTOP. We need to clear that signal?
        // If we PTRACE_SYSCALL(..., 0), the SIGSTOP is suppressed?
        // Wait, waitpid returned because of SIGSTOP.
        // If we restart with 0, the child will continue as if no signal happened?
        // Yes, that's what we want.
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        
        trace_loop(&ctx);
        
        if (ctx.mode_c) print_stats(&ctx);
    }
    
    free(ctx.bin_path);
    return 0;
}
