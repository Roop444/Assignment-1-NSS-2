/* accheck-helper.c */
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "usage: accheck-helper <user> <read|write|exec> <path>\n");
        return 1;
    }

    struct passwd *pw = getpwnam(argv[1]);
    if (!pw) {
        perror("getpwnam");
        return 1;
    }

    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        perror("setuid/setgid");
        return 1;
    }

    int ok = 0;

    if (strcmp(argv[2], "read") == 0) {
        int fd = open(argv[3], O_RDONLY);
        ok = (fd >= 0);
        if (fd >= 0) close(fd);
    } else if (strcmp(argv[2], "write") == 0) {
        int fd = open(argv[3], O_WRONLY | O_APPEND);
        ok = (fd >= 0);
        if (fd >= 0) close(fd);
    } else if (strcmp(argv[2], "exec") == 0) {
        execl(argv[3], argv[3], NULL);
        ok = 0;
    }

    printf("Kernel decision: %s\n", ok ? "ALLOW" : "DENY");
    return 0;
}

