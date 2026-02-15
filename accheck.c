#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static acl_perm_t perm_for_op(const char *op) {
    if (strcmp(op, "read") == 0)
        return ACL_READ_DATA;
    if (strcmp(op, "write") == 0)
        return ACL_WRITE_DATA;
    if (strcmp(op, "exec") == 0)
        return ACL_EXECUTE;
    return 0;
}

static int has_execute(uid_t uid, const struct stat *st) {
    /* owner */
    if (uid == st->st_uid && (st->st_mode & S_IXUSR))
        return 1;

    /* any group */
    struct passwd *pw = getpwuid(uid);
    if (!pw)
        return 0;

    int ngroups = 0;
    getgrouplist(pw->pw_name, NULL, &ngroups);

    gid_t groups[ngroups];
    getgrouplist(pw->pw_name, groups, &ngroups);

    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == st->st_gid && (st->st_mode & S_IXGRP))
            return 1;
    }

    /* other */
    if (st->st_mode & S_IXOTH)
        return 1;

    return 0;
}

static int check_traversal(uid_t uid, const char *path) {
    char tmp[PATH_MAX];
    struct stat st;

    strncpy(tmp, path, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';

    /* walk every directory component */
    for (char *p = tmp + 1; ; p++) {
        if (*p == '/' || *p == '\0') {
            char saved = *p;
            *p = '\0';

            if (strlen(tmp) > 0) {
                if (stat(tmp, &st) != 0)
                    return 0;

                if (!has_execute(uid, &st))
                    return 0;
            }

            if (saved == '\0')
                break;

            *p = '/';
        }
    }

    return 1;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "usage: accheck <user> <read|write|exec> <path>\n");
        return 1;
    }

    const char *user = argv[1];
    const char *op   = argv[2];
    const char *path = argv[3];

    acl_perm_t needed = perm_for_op(op);
    if (needed == 0) {
        fprintf(stderr, "Invalid operation\n");
        return 1;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        perror("getpwnam");
        return 1;
    }

    if (!check_traversal(pw->pw_uid, pw->pw_gid, path)) {
        printf("Prediction: DENY (directory traversal)\n");
        return 0;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        return 1;
    }

    acl_t acl = acl_get_file(path, ACL_TYPE_NFS4);
    if (!acl) {
        perror("acl_get_file");
        return 1;
    }

    int entry_id = ACL_FIRST_ENTRY;
    acl_entry_t entry;
    int allow = 0;

    /* NFSv4 ACL evaluation: first matching DENY wins, otherwise ALLOW */
    while (acl_get_entry(acl, entry_id, &entry) == 1) {
        entry_id = ACL_NEXT_ENTRY;

        acl_tag_t tag;
        acl_get_tag_type(entry, &tag);

        int applies = 0;

        if (tag == ACL_USER) {
            uid_t *u = acl_get_qualifier(entry);
            if (u && *u == pw->pw_uid)
                applies = 1;
            acl_free(u);
        } else if (tag == ACL_GROUP) {
            gid_t *g = acl_get_qualifier(entry);
            if (g && *g == pw->pw_gid)
                applies = 1;
            acl_free(g);
        } else if (tag == ACL_EVERYONE) {
            applies = 1;
        } else if (tag == ACL_USER_OBJ && pw->pw_uid == st.st_uid) {
            applies = 1;
        } else if (tag == ACL_GROUP_OBJ && pw->pw_gid == st.st_gid) {
            applies = 1;
        }

        if (!applies)
            continue;

        acl_permset_t permset;
        acl_get_permset(entry, &permset);

        if (!acl_get_perm_np(permset, needed))
            continue;

        int type;
        acl_get_entry_type_np(entry, &type);

        if (type == ACL_ENTRY_TYPE_DENY) {
            printf("Prediction: DENY (NFSv4 DENY ACE)\n");
            acl_free(acl);
            return 0;
        }

        if (type == ACL_ENTRY_TYPE_ALLOW)
            allow = 1;
    }

    acl_free(acl);

    if (allow) {
        printf("Prediction: ALLOW (NFSv4 ALLOW ACE)\n");
        return 0;
    }

    /* Fallback: POSIX mode bits */
    mode_t bit = 0;
    if (strcmp(op, "read") == 0)
        bit = (pw->pw_uid == st.st_uid) ? S_IRUSR :
              (pw->pw_gid == st.st_gid) ? S_IRGRP : S_IROTH;
    else if (strcmp(op, "write") == 0)
        bit = (pw->pw_uid == st.st_uid) ? S_IWUSR :
              (pw->pw_gid == st.st_gid) ? S_IWGRP : S_IWOTH;
    else if (strcmp(op, "exec") == 0)
        bit = (pw->pw_uid == st.st_uid) ? S_IXUSR :
              (pw->pw_gid == st.st_gid) ? S_IXGRP : S_IXOTH;

    if (st.st_mode & bit)
        printf("Prediction: ALLOW (mode bits)\n");
    else
        printf("Prediction: DENY (no matching ACL or mode permission)\n");

    return 0;
}

