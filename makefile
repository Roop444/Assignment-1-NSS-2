CC=cc
CFLAGS=-Wall -Wextra

all:
	$(CC) $(CFLAGS) accheck.c -o accheck
	$(CC) $(CFLAGS) accheck-helper.c -o accheck-helper
	$(CC) $(CFLAGS) accheck-test-read.c -o accheck-test-read
	$(CC) $(CFLAGS) accheck-test-write.c -o accheck-test-write
	$(CC) $(CFLAGS) accheck-test-exec.c -o accheck-test-exec
CC=cc
CFLAGS=-Wall -Wextra

all:
	$(CC) $(CFLAGS) accheck.c -o accheck
	$(CC) $(CFLAGS) accheck-helper.c -o accheck-helper
	$(CC) $(CFLAGS) accheck-test-read.c -o accheck-test-read
	$(CC) $(CFLAGS) accheck-test-write.c -o accheck-test-write
	$(CC) $(CFLAGS) accheck-test-exec.c -o accheck-test-exec

