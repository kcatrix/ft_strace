#include <unistd.h>
#include <signal.h>
#include <stdio.h>

void handler(int sig) {
    write(1, "Signal received\n", 16);
}

int main(void) {
    signal(SIGUSR1, handler);
    raise(SIGUSR1);
    return 0;
}
