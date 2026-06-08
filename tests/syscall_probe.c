/*
 * syscall_probe.c — exercise specific libc wrappers under why-denied.
 *
 * The behavioural suite normally drives the shim through coreutils (cat, rm,
 * chmod, ...), but those only ever reach a handful of the intercepted symbols.
 * This tiny helper performs ONE precisely-chosen libc call so the test harness
 * can cover the wrapper variants that no stock command exercises:
 *
 *   * open(O_RDWR)            — the AK_RDWR access kind (both missing-read and
 *                              missing-write sub-branches)
 *   * openat(dirfd, ...)      — the INSPECT_AT macro + resolve_at() dirfd join
 *   * creat()                 — the dedicated creat wrapper
 *   * fchmod()/fchown()       — the INSPECT_FD macro + path_from_fd() probe
 *   * open(O_RDONLY|O_DIRECTORY)
 *                            — regression for the O_TMPFILE mask fix: a plain
 *                              directory open must NOT consume a mode va_arg and
 *                              must stay completely silent on success.
 *
 * It is compiled WITHOUT the shim and run WITH it preloaded, so why-denied
 * intercepts the call exactly as it would in a real program. The outcome is
 * printed as PROBE_OK / PROBE_ERR:<errno> so assertions never depend on the
 * process exit status (which the pty harness discards).
 *
 * Usage:
 *   syscall_probe open_rdwr      <path>
 *   syscall_probe open_dir       <dir>
 *   syscall_probe openat_rdonly  <dir> <name>
 *   syscall_probe creat          <path>
 *   syscall_probe fchmod         <path>
 *   syscall_probe fchown         <path> <uid>
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int ok(void)
{
    printf("PROBE_OK\n");
    return 0;
}

static int err(void)
{
    printf("PROBE_ERR:%d\n", errno);
    return 1;
}

static int from_fd(int fd)
{
    return fd < 0 ? err() : ok();
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: syscall_probe OP ARGS...\n");
        return 2;
    }

    const char *op = argv[1];

    if (strcmp(op, "open_rdwr") == 0)
        return from_fd(open(argv[2], O_RDWR));

    if (strcmp(op, "open_dir") == 0)
        return from_fd(open(argv[2], O_RDONLY | O_DIRECTORY));

    if (strcmp(op, "creat") == 0)
        return from_fd(creat(argv[2], 0644));

    if (strcmp(op, "openat_rdonly") == 0) {
        if (argc < 4) {
            fprintf(stderr, "openat_rdonly needs <dir> <name>\n");
            return 2;
        }
        int dfd = open(argv[2], O_RDONLY | O_DIRECTORY);
        if (dfd < 0)
            return err();
        /* Keep dfd open across the openat so /proc/self/fd/<dfd> resolves
         * while why-denied inspects the denial. */
        return from_fd(openat(dfd, argv[3], O_RDONLY));
    }

    if (strcmp(op, "fchmod") == 0) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0)
            return err();
        return fchmod(fd, 0600) == 0 ? ok() : err();
    }

    if (strcmp(op, "fchown") == 0) {
        if (argc < 4) {
            fprintf(stderr, "fchown needs <path> <uid>\n");
            return 2;
        }
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0)
            return err();
        uid_t target = (uid_t)strtoul(argv[3], NULL, 10);
        return fchown(fd, target, (gid_t)-1) == 0 ? ok() : err();
    }

    fprintf(stderr, "syscall_probe: unknown op '%s'\n", op);
    return 2;
}
