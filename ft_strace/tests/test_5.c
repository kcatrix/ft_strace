#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    int i = 0;
    while (envp[i]) {
        if (i < 3) // verify we can read env
            printf("ENV: %s\n", envp[i]);
        i++;
    }
    return 0;
}
