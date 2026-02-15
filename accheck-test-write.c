#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    setuid(getuid());
    int fd = open(argv[1], O_WRONLY | O_APPEND);
    printf("%s\n", fd >= 0 ? "WRITE OK" : "WRITE DENIED");
    return 0;
}

