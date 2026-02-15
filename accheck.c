#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <user> <read|write|exec> <path>\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 4)
        usage(argv[0]);

    const char *user = argv[1];
    const char *op   = argv[2];
    const char *path = argv[3];

    int mode;
    if (strcmp(op, "read") == 0)
        mode = R_OK;
    else if (strcmp(op, "write") == 0)
        mode = W_OK;
    else if (strcmp(op, "exec") == 0)
        mode = X_OK;
    else
        usage(argv[0]);

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        perror("getpwnam");
        return 1;
    }

    uid_t old_euid = geteuid();
    gid_t old_egid = getegid();

    /* Switch identity */
    if (setegid(pw->pw_gid) != 0) {
        perror("setegid");
        return 1;
    }

    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        perror("initgroups");
        return 1;
    }

    if (seteuid(pw->pw_uid) != 0) {
        perror("seteuid");
        return 1;
    }

    /* Ask the kernel (NO ACCESS ATTEMPT) */
    int ret = faccessat(AT_FDCWD, path, mode, AT_EACCESS);

    /* Restore identity */
    seteuid(old_euid);
    setegid(old_egid);

    if (ret == 0) {
        printf("Prediction: ALLOW\n");
    } else {
        if (errno == EACCES)
            printf("Prediction: DENY\n");
        else
            perror("faccessat");
    }

    return 0;
}
