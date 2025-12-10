#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
    int fd = open("/tmp/delmen", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    char buf[1024];
    ssize_t n = read(fd, buf, 1024);
    printf("Read %ld bytes\n", n);
    close(fd);
    return 0;
}
