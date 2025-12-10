#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        write(1, "Child\n", 6);
    } else {
        wait(NULL);
        write(1, "Parent\n", 7);
    }
    return 0;
}
