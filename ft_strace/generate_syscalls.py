import re
import os

def parse_header(path):
    syscalls = {}
    with open(path, 'r') as f:
        for line in f:
            # Match #define __NR_name number
            m = re.match(r'^#define\s+__NR_(\w+)\s+(\d+)', line)
            if m:
                name = m.group(1)
                num = int(m.group(2))
                syscalls[num] = name
    return syscalls

def write_c_header(syscalls_64, syscalls_32, out_path):
    with open(out_path, 'w') as f:
        f.write("#ifndef SYSCALL_TABLE_H\n#define SYSCALL_TABLE_H\n\n")
        
        f.write("static const char *syscall_names_64[] __attribute__((unused)) = {\n")
        max_64 = max(syscalls_64.keys()) if syscalls_64 else 0
        for i in range(max_64 + 1):
            name = syscalls_64.get(i, "unknown")
            f.write(f'\t"{name}",\n')
        f.write("};\n\n")
        
        f.write("static const char *syscall_names_32[] __attribute__((unused)) = {\n")
        max_32 = max(syscalls_32.keys()) if syscalls_32 else 0
        for i in range(max_32 + 1):
            name = syscalls_32.get(i, "unknown")
            f.write(f'\t"{name}",\n')
        f.write("};\n\n")
        
        f.write(f"#define MAX_SYSCALL_64 {max_64}\n")
        f.write(f"#define MAX_SYSCALL_32 {max_32}\n")
        f.write("#endif\n")

if __name__ == "__main__":
    s64 = parse_header('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
    s32 = parse_header('/usr/include/x86_64-linux-gnu/asm/unistd_32.h')
    write_c_header(s64, s32, 'inc/syscall_table.h')
