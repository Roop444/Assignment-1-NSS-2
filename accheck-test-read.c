#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    setuid(getuid());
    int fd = open(argv[1], O_RDONLY);
    printf("%s\n", fd >= 0 ? "READ OK" : "READ DENIED");
    return 0;
}

