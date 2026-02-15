#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    setuid(getuid());
    execl(argv[1], argv[1], NULL);
    perror("exec");
    return 1;
}

