/*
 * why-denied — global "Permission Denied" root-cause analyzer.
 *
 * This is an LD_PRELOAD shared library that transparently wraps a set of
 * glibc syscall wrappers (open, execve, unlink, chmod, ...). When, and ONLY
 * when, one of those calls fails with EACCES or EPERM during an interactive
 * human session, the library performs a careful, read-only investigation and
 * prints a human-readable root cause + remediation to STDERR.
 *
 * Design contract (do not break these):
 *   1. The real syscall ALWAYS runs first and its return value + errno are the
 *      values the application observes. We never change control flow.
 *   2. On success (or any non EACCES/EPERM failure) we do ZERO extra work:
 *      no stat(), no allocation, no I/O. The hot path is a single branch.
 *   3. We are fail-safe: if our own inspection logic fails for any reason we
 *      silently restore the original errno and return the original result.
 *   4. We are reentrancy-safe: a thread-local guard prevents infinite
 *      recursion should any function we call internally be itself intercepted.
 *   5. We only ever engage when STDERR is a TTY (an interactive session).
 *      Daemons, cron jobs and pipelines get a pure pass-through.
 *
 * The library keeps no mutable global state beyond the lazily-cached real
 * function pointers and a single load-time "disabled" flag, so it is safe to
 * use in heavily multi-threaded programs.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Inode attribute flags / ioctl (from <linux/fs.h>); hard-coded so the library
 * builds on toolchains where that header is unavailable. Used to detect
 * immutable/append-only files (chattr +i/+a) before blaming an LSM. */
#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL 0x00000010
#endif
#ifndef FS_APPEND_FL
#define FS_APPEND_FL 0x00000020
#endif

/* Filesystem magic numbers (from <linux/magic.h>); hard-coded so the library
 * builds on toolchains where that header is unavailable. */
#define WD_NFS_SUPER_MAGIC 0x6969UL
#define WD_SMB_SUPER_MAGIC 0x517BUL
#define WD_CIFS_MAGIC_NUMBER 0xFF534D42UL
#define WD_SMB2_MAGIC_NUMBER 0xFE534D42UL
#define WD_FUSE_SUPER_MAGIC 0x65735546UL
#define WD_9P_MAGIC 0x01021997UL
#define WD_AFS_SUPER_MAGIC 0x5346414FUL

/* -------------------------------------------------------------------------
 * Global state (intentionally minimal).
 * ---------------------------------------------------------------------- */

/* Set once, at library load, before any application threads start. After the
 * constructor returns it is read-only, so unsynchronized reads are safe. */
static int g_disabled = 0;

/* Per-thread reentrancy guard. If our inspection code ever calls back into one
 * of the intercepted wrappers we must not recurse into analysis again. */
static __thread int g_in_inspect = 0;

/* -------------------------------------------------------------------------
 * Access classification used by the triage engine.
 * ---------------------------------------------------------------------- */

enum access_kind {
    AK_READ,   /* needs read bit on the target file */
    AK_WRITE,  /* needs write bit on the target (or create into parent) */
    AK_RDWR,   /* O_RDWR: needs BOTH read and write bits on the target */
    AK_EXEC,   /* needs execute bit on the target file */
    AK_CREATE, /* needs write + search on the parent directory */
    AK_DELETE, /* like CREATE, plus sticky-bit consideration */
    AK_CHMOD,  /* chmod/fchmod/fchmodat: requires ownership (or root) */
    AK_CHOWN   /* chown/fchown/fchownat: owner can't give away / set group */
};

/* -------------------------------------------------------------------------
 * Lazily-resolved, cached real function pointers.
 * ---------------------------------------------------------------------- */

static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_creat)(const char *, mode_t);
/* glibc large-file (LFS) variants. Programs built with _FILE_OFFSET_BITS=64
 * (e.g. Debian's dash) call these instead of the plain names. */
static int (*real_open64)(const char *, int, ...);
static int (*real_openat64)(int, const char *, int, ...);
static int (*real_creat64)(const char *, mode_t);
static int (*real_execve)(const char *, char *const[], char *const[]);
static int (*real_execveat)(int, const char *, char *const[], char *const[],
                            int);
static int (*real_mkdir)(const char *, mode_t);
static int (*real_mkdirat)(int, const char *, mode_t);
static int (*real_rmdir)(const char *);
static int (*real_unlink)(const char *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_chmod)(const char *, mode_t);
static int (*real_fchmod)(int, mode_t);
static int (*real_fchmodat)(int, const char *, mode_t, int);
static int (*real_chown)(const char *, uid_t, gid_t);
static int (*real_fchown)(int, uid_t, gid_t);
static int (*real_fchownat)(int, const char *, uid_t, gid_t, int);

/*
 * Resolve a real symbol exactly once and cache it. Two threads racing here is
 * harmless: dlsym() is idempotent and the pointer-sized store is atomic. The
 * release/acquire pair guarantees that a thread which observes a non-NULL
 * pointer also observes a fully-formed value.
 */
static void resolve_sym(void **slot, const char *name)
{
    void *sym = dlsym(RTLD_NEXT, name);
    __atomic_store_n(slot, sym, __ATOMIC_RELEASE);
}

#define ENSURE(ptr, name)                                                      \
    do {                                                                       \
        if (__builtin_expect(                                                  \
                __atomic_load_n((void **)&(ptr), __ATOMIC_ACQUIRE) == NULL,    \
                0)) {                                                          \
            resolve_sym((void **)&(ptr), (name));                              \
        }                                                                      \
    } while (0)

/* -------------------------------------------------------------------------
 * Output helper: format a one-line message and write it directly to STDERR.
 *
 * We deliberately avoid stdio's buffered printf family: an intercepted call
 * may happen while the C library holds an internal stdio lock, and re-entering
 * it could deadlock. write(2) on a stack buffer is reentrancy-safe and never
 * allocates.
 *
 * NOTE: this is NOT async-signal-safe — vsnprintf() is not on the AS-safe list.
 * That is fine: we only run from normal application context after a failed libc
 * call (never from a signal handler) and behind the per-thread reentrancy guard.
 * ---------------------------------------------------------------------- */
static void emitf(const char *fmt, ...)
{
    char body[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);

    char line[896];
    int n = snprintf(line, sizeof line, "[why-denied] %s\n", body);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof line)
        n = (int)sizeof line - 1;
    (void)write(STDERR_FILENO, line, (size_t)n);
}

/* -------------------------------------------------------------------------
 * Small POSIX permission helpers.
 * ---------------------------------------------------------------------- */

/* Is the calling process a member of group g (effective or supplementary)?
 * Returns 1 = member, 0 = not a member, -1 = membership could not be
 * determined (so the caller must not assert a definitive group/other class). */
static int in_group(gid_t g)
{
    if (getegid() == g)
        return 1;
    /* Fixed stack buffer first: avoids malloc in the common case. */
    gid_t list[256];
    int n = getgroups((int)(sizeof list / sizeof list[0]), list);
    if (n < 0) {
        /* The process belongs to more groups than our buffer holds
         * (getgroups returned EINVAL). Re-query the exact count and use a
         * heap buffer. This only happens on the cold diagnostic path. */
        int count = getgroups(0, NULL);
        if (count > 0) {
            gid_t *dyn = malloc((size_t)count * sizeof *dyn);
            if (dyn != NULL) {
                int m = getgroups(count, dyn);
                int found = 0;
                for (int i = 0; i < m; i++)
                    if (dyn[i] == g) {
                        found = 1;
                        break;
                    }
                free(dyn);
                if (m >= 0)
                    return found;
            }
        }
        return -1; /* genuinely unknown — don't claim "not a member" */
    }
    for (int i = 0; i < n; i++)
        if (list[i] == g)
            return 1;
    return 0;
}

enum { CLASS_OWNER = 0, CLASS_GROUP = 1, CLASS_OTHER = 2 };

/* Which permission class applies to the effective user for this object? */
static int eff_class(const struct stat *st)
{
    if (st->st_uid == geteuid())
        return CLASS_OWNER;
    int member = in_group(st->st_gid);
    if (member == 1)
        return CLASS_GROUP;
    if (member < 0)
        /* Membership is genuinely unknown (couldn't enumerate groups). We
         * already know the caller is not the owner; assume the group class
         * rather than asserting "other", since a wrong "grants to ALL users"
         * other-class hint would be the more harmful misattribution. */
        return CLASS_GROUP;
    return CLASS_OTHER;
}

/* The 3 rwx bits (value 0..7) that apply to the given class. */
static int class_bits(const struct stat *st, int cls)
{
    switch (cls) {
    case CLASS_OWNER:
        return (int)((st->st_mode & S_IRWXU) >> 6);
    case CLASS_GROUP:
        return (int)((st->st_mode & S_IRWXG) >> 3);
    default:
        return (int)(st->st_mode & S_IRWXO);
    }
}

static const char *class_word(int cls)
{
    return cls == CLASS_OWNER   ? "owner"
           : cls == CLASS_GROUP ? "group"
                                : "other";
}

static char class_char(int cls)
{
    return cls == CLASS_OWNER ? 'u' : cls == CLASS_GROUP ? 'g' : 'o';
}

/* -------------------------------------------------------------------------
 * Path helpers for the *at() family and fd-based calls.
 * ---------------------------------------------------------------------- */

/* A /proc/self/fd readlink result is only a usable path if it is absolute and
 * not a synthetic name (pipe:[...], socket:[...], anon_inode:..., or a
 * "<path> (deleted)" tombstone). Returns 1 if the link looks like a real path. */
static int is_real_path_link(const char *link, size_t len)
{
    if (len == 0 || link[0] != '/')
        return 0;
    static const char deleted[] = " (deleted)";
    size_t dl = sizeof deleted - 1;
    if (len >= dl && memcmp(link + len - dl, deleted, dl) == 0)
        return 0;
    return 1;
}

/*
 * Best-effort resolution of an *at() path to something stat() can use.
 *  - Absolute paths and AT_FDCWD-relative paths are returned unchanged
 *    (a relative path already resolves against the cwd for stat()).
 *  - A dirfd-relative path is joined with the directory that dirfd refers to,
 *    discovered via /proc/self/fd/<dirfd>.
 *  - An empty path with a dirfd means AT_EMPTY_PATH: use the fd target itself.
 *  - Synthetic fd targets (pipe:/socket:/anon_inode:/deleted) yield NULL so the
 *    caller emits no misleading message.
 *  - If anything is unresolvable we degrade gracefully to the raw path.
 */
static const char *resolve_at(int dirfd, const char *path, char *buf,
                              size_t bufsz)
{
    if (path != NULL && path[0] == '/')
        return path; /* already absolute */
    if (dirfd == AT_FDCWD || path == NULL)
        return path; /* relative-to-cwd (stat handles it) or nothing to do */

    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);

    char dir[PATH_MAX];
    ssize_t r = readlink(link, dir, sizeof dir - 1);
    if (r < 0)
        return path; /* degrade to the raw path */
    dir[r] = '\0';

    /* Reject synthetic dirfd targets: building "pipe:[...]/foo" would only
     * yield a misleading diagnosis. Bail to no message. */
    if (!is_real_path_link(dir, (size_t)r))
        return NULL;

    /* AT_EMPTY_PATH (e.g. execveat(fd, "", ..., AT_EMPTY_PATH)): the operation
     * targets the fd itself. Use the readlink target verbatim — appending "/"
     * would produce a path that cannot be stat()ed. */
    if (path[0] == '\0') {
        int n = snprintf(buf, bufsz, "%s", dir);
        if (n < 0 || (size_t)n >= bufsz)
            return NULL;
        return buf;
    }

    int n = snprintf(buf, bufsz, "%s/%s", dir, path);
    if (n < 0 || (size_t)n >= bufsz)
        return path; /* truncated or error: degrade to the raw path */
    return buf;
}

/* Resolve the path backing an open fd (for fchmod/fchown). */
static const char *path_from_fd(int fd, char *buf, size_t bufsz)
{
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t r = readlink(link, buf, bufsz - 1);
    if (r < 0)
        return NULL;
    buf[r] = '\0';
    /* Don't treat a synthetic name (pipe:/socket:/anon_inode:) or a deleted
     * tombstone as a real path; doing so would produce a misleading message. */
    if (!is_real_path_link(buf, (size_t)r))
        return NULL;
    return buf;
}

/* Compute the parent directory of path into buf. Handles trailing slashes,
 * the filesystem root and relative paths with no slash. */
static void parent_of(const char *path, char *buf, size_t bufsz)
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') /* drop trailing slashes */
        len--;

    size_t slash = len;
    while (slash > 0 && path[slash - 1] != '/')
        slash--;

    if (slash == 0) {
        /* no slash at all: parent is the current directory */
        snprintf(buf, bufsz, ".");
    } else if (slash == 1) {
        /* path is "/something": parent is root */
        snprintf(buf, bufsz, "/");
    } else {
        size_t plen = slash - 1; /* exclude the separating slash */
        if (plen >= bufsz)
            plen = bufsz - 1;
        memcpy(buf, path, plen);
        buf[plen] = '\0';
    }
}

/* -------------------------------------------------------------------------
 * Advanced (non-POSIX) triage. Reached only when the standard permission math
 * says the user SHOULD have been granted access yet the kernel still refused.
 * Order: ACL  ->  Network filesystem  ->  Mandatory Access Control.
 * ---------------------------------------------------------------------- */

/*
 * NOTE on async-signal-safety: this diagnostic path is deliberately NOT
 * async-signal-safe. emitf() uses vsnprintf(), and the libacl probe below
 * (acl_get_file) allocates. We only ever run after a *failed* libc call from
 * application context (never from a signal handler) and behind the per-thread
 * reentrancy guard, so this is acceptable. The non-libacl build instead uses a
 * single allocation-free getxattr() probe; prefer that build (omit HAVE_LIBACL)
 * if you need the interposed path to avoid heap allocation entirely.
 */
#ifdef HAVE_LIBACL
#include <sys/acl.h>

/* An object carries an "extended" ACL when it has at least one named user,
 * named group or mask entry beyond the three base (owner/group/other) ones.
 * Trade-off: acl_get_file() allocates; the #else branch below is allocation-
 * free (getxattr) and is preferred where async-signal-safety matters. */
static int has_extended_acl(const char *path)
{
    acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
    if (acl == NULL)
        return 0;

    int extended = 0;
    acl_entry_t entry;
    for (int r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); r == 1;
         r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry)) {
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) == 0 &&
            (tag == ACL_USER || tag == ACL_GROUP || tag == ACL_MASK)) {
            extended = 1;
            break;
        }
    }
    acl_free(acl);
    return extended;
}
#else
#include <sys/xattr.h>

/* Without libacl we fall back to probing for the POSIX ACL xattr. A positive
 * length means an access ACL is attached. */
static int has_extended_acl(const char *path)
{
    ssize_t r = getxattr(path, "system.posix_acl_access", NULL, 0);
    return r > 0;
}
#endif

static void advanced_triage(const char *path)
{
    if (has_extended_acl(path)) {
        emitf("Blocked by Extended Access Control List (ACLs). "
              "Inspect with 'getfacl %s'.",
              path);
        return;
    }

    struct statfs sfs;
    if (statfs(path, &sfs) == 0) {
        switch ((unsigned long)sfs.f_type) {
        case WD_NFS_SUPER_MAGIC:
            emitf("Blocked by Network Filesystem (NFS) export rules or "
                  "Root Squashing.");
            return;
        case WD_CIFS_MAGIC_NUMBER:
        case WD_SMB2_MAGIC_NUMBER:
        case WD_SMB_SUPER_MAGIC:
            emitf("Blocked by Network Filesystem (CIFS/SMB) share "
                  "permissions or Root Squashing.");
            return;
        case WD_9P_MAGIC:
        case WD_AFS_SUPER_MAGIC:
        case WD_FUSE_SUPER_MAGIC:
            emitf("Blocked by Network/Userspace Filesystem export rules.");
            return;
        default:
            break;
        }
    }

    /* Before blaming an LSM, probe for an immutable / append-only inode flag
     * (chattr +i / +a) — a frequent, easily-missed cause of EPERM that POSIX
     * bits and ACLs cannot express. Cold path only; we gracefully ignore
     * filesystems that don't support FS_IOC_GETFLAGS (ENOTTY/EOPNOTSUPP) or a
     * target we cannot open. The open() here is our own interposed wrapper but
     * the reentrancy guard is set, so it will not recurse into analysis. */
    int afd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (afd >= 0) {
        int attrs = 0;
        if (ioctl(afd, FS_IOC_GETFLAGS, &attrs) == 0) {
            if (attrs & FS_IMMUTABLE_FL) {
                close(afd);
                emitf("Cannot modify '%s': the file is IMMUTABLE (chattr +i). "
                      "Clear it with 'chattr -i %s' (needs root / "
                      "CAP_LINUX_IMMUTABLE).",
                      path, path);
                return;
            }
            if (attrs & FS_APPEND_FL) {
                close(afd);
                emitf("Cannot modify '%s': the file is APPEND-ONLY "
                      "(chattr +a); only appends are allowed. Clear it with "
                      "'chattr -a %s' (needs root / CAP_LINUX_IMMUTABLE).",
                      path, path);
                return;
            }
        }
        close(afd);
    }

    /* Nothing in POSIX/ACL/NFS/attributes explains it. Stay non-authoritative
     * rather than asserting an LSM: it's the most likely cause but not the only
     * one, and a confident wrong answer is worse than an honest pointer. */
    emitf("Could not attribute this to POSIX/ACL/NFS permissions — likely a "
          "Linux Security Module (SELinux/AppArmor), a file attribute "
          "(chattr +i/+a), or another kernel policy. Check 'dmesg' or "
          "'audit2why'.");
}

/* -------------------------------------------------------------------------
 * Standard POSIX evaluation helpers.
 * ---------------------------------------------------------------------- */

static void report_missing_perm(const char *path, const char *verb,
                                const char *permword, char permchar, int cls)
{
    /* The 'other' class is the only one that can be fixed solely by widening
     * the mode bits for this caller, but doing so grants the same access to
     * every user on the system — flag that so nobody reaches for it blindly. */
    if (cls == CLASS_OTHER) {
        emitf("Cannot %s '%s': Missing %s %s permission. Run 'chmod %c+%c %s' "
              "(warning: grants %s access to ALL users on the system).",
              verb, path, class_word(cls), permword, class_char(cls), permchar,
              path, permword);
        return;
    }
    emitf("Cannot %s '%s': Missing %s %s permission. Run 'chmod %c+%c %s'.",
          verb, path, class_word(cls), permword, class_char(cls), permchar,
          path);
}

/*
 * Walk every ancestor directory of a path and report the first one the
 * effective user cannot search (missing execute bit). Returns 1 if it emitted
 * a diagnosis, 0 otherwise (so the caller can fall through to the advanced
 * engine). Relative paths are resolved against getcwd() (cold path only) so
 * search-bit denials like `cat foo/bar` are diagnosed instead of escalating
 * to the LSM catch-all; if getcwd() fails we degrade to the old behavior.
 */
static int report_missing_search(const char *path)
{
    char abspath[PATH_MAX];
    if (path[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof cwd) == NULL)
            return 0; /* cannot resolve: degrade, let caller fall back */
        int an = snprintf(abspath, sizeof abspath, "%s/%s", cwd, path);
        if (an < 0 || (size_t)an >= sizeof abspath)
            return 0;
        path = abspath;
    }

    size_t n = strlen(path);
    if (n == 0 || n >= PATH_MAX)
        return 0;

    char buf[PATH_MAX];
    for (size_t i = 1; i < n; i++) {
        if (path[i] != '/')
            continue;

        memcpy(buf, path, i);
        buf[i] = '\0';

        struct stat st;
        if (stat(buf, &st) != 0)
            return 0; /* a higher ancestor blocked us; let caller fall back */
        if (!S_ISDIR(st.st_mode))
            continue;

        int cls = eff_class(&st);
        if (!(class_bits(&st, cls) & 1)) {
            if (cls == CLASS_OTHER)
                emitf("Cannot traverse path: Missing execute (search) "
                      "permission on directory '%s'. Run 'chmod o+x %s' "
                      "(warning: grants search access to ALL users on the "
                      "system).",
                      buf, buf);
            else
                emitf("Cannot traverse path: Missing execute (search) "
                      "permission on directory '%s'. Run 'chmod %c+x %s'.",
                      buf, class_char(cls), buf);
            return 1;
        }
    }
    return 0;
}

/* Check that the effective user can both write to and search the parent
 * directory of path (the precondition for creating or deleting an entry).
 * Returns 1 if a missing bit was diagnosed, 0 to fall through. */
static int check_parent_writable(const char *parent)
{
    struct stat pst;
    if (stat(parent, &pst) != 0) {
        if (errno == EACCES)
            return report_missing_search(parent);
        return 0;
    }

    int cls = eff_class(&pst);
    int bits = class_bits(&pst, cls);

    if (!(bits & 2)) {
        report_missing_perm(parent, "write into directory", "write", 'w', cls);
        return 1;
    }
    if (!(bits & 1)) {
        report_missing_perm(parent, "search directory", "execute", 'x', cls);
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * The triage entry point.
 *
 * Invariant: errno on entry holds the EACCES/EPERM the kernel returned. We
 * save it immediately and restore it on every exit so the application never
 * sees the errno produced by our own probing syscalls.
 * ---------------------------------------------------------------------- */
static void analyze_denial(const char *path, enum access_kind kind)
{
    int saved = errno;

    if (path == NULL)
        goto done;

    struct stat st;
    char parent[PATH_MAX];

    switch (kind) {
    case AK_CHMOD:
    case AK_CHOWN: {
        /* lstat (not stat): chmod/chown ownership rules are about the named
         * object itself, and fchmodat/fchownat may carry AT_SYMLINK_NOFOLLOW.
         * Using lstat avoids blaming/inspecting a symlink's target. */
        if (lstat(path, &st) == 0) {
            uid_t euid = geteuid();
            if (euid != 0 && st.st_uid != euid) {
                emitf("Cannot change attributes of '%s': You are not the owner "
                      "(owned by uid %u). Only the owner or root may change "
                      "permissions/ownership.",
                      path, (unsigned)st.st_uid);
                break;
            }
            if (kind == AK_CHOWN && euid != 0 && st.st_uid == euid) {
                /* The caller owns the file but chown still failed: an
                 * unprivileged process may not give a file away, nor set a
                 * group it does not belong to. That requires root/CAP_CHOWN. */
                emitf("Cannot change ownership of '%s': you own it, but "
                      "changing a file's owner (or setting a group you don't "
                      "belong to) requires root or CAP_CHOWN.",
                      path);
                break;
            }
            /* Owner (or root) yet still EPERM: something beyond POSIX. */
            advanced_triage(path);
        } else if (errno == EACCES) {
            if (!report_missing_search(path))
                advanced_triage(path);
        }
        break;
    }

    case AK_CREATE:
    case AK_DELETE: {
        parent_of(path, parent, sizeof parent);
        if (check_parent_writable(parent))
            break;

        /* For deletes, a sticky-bit directory (e.g. /tmp) only lets the file's
         * owner (or the directory owner, or root) remove an entry. */
        if (kind == AK_DELETE) {
            struct stat pst, tst;
            /* lstat on the target: unlink/rmdir act on the entry itself and
             * never follow a final symlink, so the entry's own owner is what
             * the sticky-bit rule checks. stat on the parent is correct — we
             * want the real directory the entry lives in. */
            if (stat(parent, &pst) == 0 && (pst.st_mode & S_ISVTX) &&
                lstat(path, &tst) == 0) {
                uid_t euid = geteuid();
                if (euid != 0 && tst.st_uid != euid && pst.st_uid != euid) {
                    emitf("Cannot delete '%s': Directory '%s' has the sticky "
                          "bit set; only the file's owner (uid %u) or root may "
                          "delete it.",
                          path, parent, (unsigned)tst.st_uid);
                    break;
                }
            }
        }
        /* Parent permissions look fine: escalate to advanced triage. */
        advanced_triage(parent);
        break;
    }

    case AK_READ:
    case AK_WRITE:
    case AK_RDWR:
    case AK_EXEC: {
        if (stat(path, &st) == 0) {
            int cls = eff_class(&st);
            int bits = class_bits(&st, cls);

            /* O_RDWR needs BOTH read and write bits. Report whichever is
             * actually missing so a missing read bit on an O_RDWR open is not
             * misattributed to a write/LSM problem. */
            if (kind == AK_RDWR) {
                if (!(bits & 4)) {
                    report_missing_perm(path, "READ from", "read", 'r', cls);
                    break;
                }
                if (!(bits & 2)) {
                    report_missing_perm(path, "WRITE to", "write", 'w', cls);
                    break;
                }
                advanced_triage(path);
                break;
            }

            int want;
            const char *verb, *permword;
            char permchar;
            if (kind == AK_READ) {
                want = 4;
                verb = "READ from";
                permword = "read";
                permchar = 'r';
            } else if (kind == AK_WRITE) {
                want = 2;
                verb = "WRITE to";
                permword = "write";
                permchar = 'w';
            } else {
                want = 1;
                verb = "EXECUTE";
                permword = "execute";
                permchar = 'x';
            }

            if (!(bits & want)) {
                report_missing_perm(path, verb, permword, permchar, cls);
                break;
            }

            /* The bit is present. For EXEC, a "noexec" mount is a common,
             * non-obvious cause that POSIX bits cannot express. */
            if (kind == AK_EXEC) {
                struct statvfs vfs;
                if (statvfs(path, &vfs) == 0 && (vfs.f_flag & ST_NOEXEC)) {
                    emitf("Cannot EXECUTE '%s': The filesystem is mounted "
                          "'noexec'. Remount without noexec or relocate the "
                          "binary.",
                          path);
                    break;
                }
            }
            advanced_triage(path);
        } else if (errno == EACCES) {
            /* Could not even stat the target: most likely a parent directory
             * lacks search permission. */
            if (!report_missing_search(path))
                advanced_triage(path);
        } else if ((kind == AK_WRITE || kind == AK_RDWR) &&
                   errno == ENOENT) {
            /* open(O_CREAT) on a missing file fails in the parent directory. */
            parent_of(path, parent, sizeof parent);
            if (!check_parent_writable(parent))
                advanced_triage(parent);
        }
        break;
    }
    }

done:
    errno = saved;
}

/* -------------------------------------------------------------------------
 * Inspection epilogue macros, shared by every wrapper.
 *
 * The hot path is exactly the first condition: if we are disabled or the call
 * succeeded we do nothing at all. Everything else lives behind that branch.
 * ---------------------------------------------------------------------- */

#define INSPECT(path, kind)                                                    \
    do {                                                                       \
        if (!g_disabled && ret == -1) {                                        \
            int _e = errno;                                                    \
            if ((_e == EACCES || _e == EPERM) && !g_in_inspect) {              \
                g_in_inspect = 1;                                              \
                analyze_denial((path), (kind));                                \
                g_in_inspect = 0;                                              \
            }                                                                  \
            errno = _e;                                                        \
        }                                                                      \
    } while (0)

#define INSPECT_AT(dirfd, path, kind)                                          \
    do {                                                                       \
        if (!g_disabled && ret == -1) {                                        \
            int _e = errno;                                                    \
            if ((_e == EACCES || _e == EPERM) && !g_in_inspect) {              \
                g_in_inspect = 1;                                              \
                char _rb[PATH_MAX];                                            \
                const char *_rp =                                              \
                    resolve_at((dirfd), (path), _rb, sizeof _rb);              \
                analyze_denial(_rp, (kind));                                   \
                g_in_inspect = 0;                                              \
            }                                                                  \
            errno = _e;                                                        \
        }                                                                      \
    } while (0)

#define INSPECT_FD(fd, kind)                                                   \
    do {                                                                       \
        if (!g_disabled && ret == -1) {                                        \
            int _e = errno;                                                    \
            if ((_e == EACCES || _e == EPERM) && !g_in_inspect) {              \
                g_in_inspect = 1;                                              \
                char _rb[PATH_MAX];                                            \
                const char *_rp = path_from_fd((fd), _rb, sizeof _rb);         \
                if (_rp != NULL)                                               \
                    analyze_denial(_rp, (kind));                               \
                g_in_inspect = 0;                                              \
            }                                                                  \
            errno = _e;                                                        \
        }                                                                      \
    } while (0)

/* -------------------------------------------------------------------------
 * Intercepted wrappers.
 * ---------------------------------------------------------------------- */

/* Classify an open()-family access mode. O_RDWR needs BOTH the read and write
 * bits, so it maps to AK_RDWR (not AK_WRITE) — otherwise a missing read bit on
 * an O_RDWR open would be misreported as a write/LSM problem. A bare O_CREAT
 * (even with O_RDONLY) still needs to create the entry into the parent. */
static enum access_kind open_access_kind(int flags)
{
    int amode = flags & O_ACCMODE;
    if (amode == O_RDWR)
        return AK_RDWR;
    if (amode == O_WRONLY)
        return AK_WRITE;
    if (flags & O_CREAT)
        return AK_WRITE;
    return AK_READ;
}

/* open / openat are variadic: the optional mode_t is only present when the
 * flags request file creation (O_CREAT or O_TMPFILE). We extract it via
 * va_arg and always forward it — a spurious extra argument is ignored by the
 * underlying call when no creation flag is set. */
int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode =
            (mode_t)va_arg(ap, int); /* mode_t is promoted to int in varargs */
        va_end(ap);
    }

    ENSURE(real_open, "open");
    int ret = real_open(pathname, flags, mode);

    enum access_kind kind = open_access_kind(flags);
    INSPECT(pathname, kind);
    return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    ENSURE(real_openat, "openat");
    int ret = real_openat(dirfd, pathname, flags, mode);

    enum access_kind kind = open_access_kind(flags);
    INSPECT_AT(dirfd, pathname, kind);
    return ret;
}

int creat(const char *pathname, mode_t mode)
{
    ENSURE(real_creat, "creat");
    int ret = real_creat(pathname, mode);
    INSPECT(pathname, AK_WRITE);
    return ret;
}

/* Large-file (LFS) variants. Identical behaviour to their plain counterparts;
 * we intercept them because glibc programs compiled with _FILE_OFFSET_BITS=64
 * (notably Debian's dash) emit calls to these symbols instead. */
int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    ENSURE(real_open64, "open64");
    /* musl >= 1.2.4 dropped the *64 aliases, so dlsym(RTLD_NEXT, "open64")
     * can legitimately return NULL. Fall back to plain open() rather than
     * dereferencing a NULL function pointer. */
    int ret;
    if (real_open64 != NULL) {
        ret = real_open64(pathname, flags, mode);
    } else {
        ENSURE(real_open, "open");
        ret = real_open(pathname, flags, mode);
    }

    enum access_kind kind = open_access_kind(flags);
    INSPECT(pathname, kind);
    return ret;
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    ENSURE(real_openat64, "openat64");
    /* See open64(): the *64 alias may be absent on musl >= 1.2.4. */
    int ret;
    if (real_openat64 != NULL) {
        ret = real_openat64(dirfd, pathname, flags, mode);
    } else {
        ENSURE(real_openat, "openat");
        ret = real_openat(dirfd, pathname, flags, mode);
    }

    enum access_kind kind = open_access_kind(flags);
    INSPECT_AT(dirfd, pathname, kind);
    return ret;
}

int creat64(const char *pathname, mode_t mode)
{
    ENSURE(real_creat64, "creat64");
    /* See open64(): the *64 alias may be absent on musl >= 1.2.4. */
    int ret;
    if (real_creat64 != NULL) {
        ret = real_creat64(pathname, mode);
    } else {
        ENSURE(real_creat, "creat");
        ret = real_creat(pathname, mode);
    }
    INSPECT(pathname, AK_WRITE);
    return ret;
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    ENSURE(real_execve, "execve");
    int ret = real_execve(pathname, argv, envp);
    INSPECT(pathname, AK_EXEC);
    return ret;
}

int execveat(int dirfd, const char *pathname, char *const argv[],
             char *const envp[], int flags)
{
    ENSURE(real_execveat, "execveat");
    int ret = real_execveat(dirfd, pathname, argv, envp, flags);
    INSPECT_AT(dirfd, pathname, AK_EXEC);
    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    ENSURE(real_mkdir, "mkdir");
    int ret = real_mkdir(pathname, mode);
    INSPECT(pathname, AK_CREATE);
    return ret;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    ENSURE(real_mkdirat, "mkdirat");
    int ret = real_mkdirat(dirfd, pathname, mode);
    INSPECT_AT(dirfd, pathname, AK_CREATE);
    return ret;
}

int rmdir(const char *pathname)
{
    ENSURE(real_rmdir, "rmdir");
    int ret = real_rmdir(pathname);
    INSPECT(pathname, AK_DELETE);
    return ret;
}

int unlink(const char *pathname)
{
    ENSURE(real_unlink, "unlink");
    int ret = real_unlink(pathname);
    INSPECT(pathname, AK_DELETE);
    return ret;
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    ENSURE(real_unlinkat, "unlinkat");
    int ret = real_unlinkat(dirfd, pathname, flags);
    INSPECT_AT(dirfd, pathname, AK_DELETE);
    return ret;
}

int chmod(const char *pathname, mode_t mode)
{
    ENSURE(real_chmod, "chmod");
    int ret = real_chmod(pathname, mode);
    INSPECT(pathname, AK_CHMOD);
    return ret;
}

int fchmod(int fd, mode_t mode)
{
    ENSURE(real_fchmod, "fchmod");
    int ret = real_fchmod(fd, mode);
    INSPECT_FD(fd, AK_CHMOD);
    return ret;
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
    ENSURE(real_fchmodat, "fchmodat");
    int ret = real_fchmodat(dirfd, pathname, mode, flags);
    INSPECT_AT(dirfd, pathname, AK_CHMOD);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    ENSURE(real_chown, "chown");
    int ret = real_chown(pathname, owner, group);
    INSPECT(pathname, AK_CHOWN);
    return ret;
}

int fchown(int fd, uid_t owner, gid_t group)
{
    ENSURE(real_fchown, "fchown");
    int ret = real_fchown(fd, owner, group);
    INSPECT_FD(fd, AK_CHOWN);
    return ret;
}

int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group,
             int flags)
{
    ENSURE(real_fchownat, "fchownat");
    int ret = real_fchownat(dirfd, pathname, owner, group, flags);
    INSPECT_AT(dirfd, pathname, AK_CHOWN);
    return ret;
}

/* -------------------------------------------------------------------------
 * Library load-time gate.
 *
 * We only ever engage for interactive human sessions, identified by STDERR
 * being a TTY. Non-interactive contexts (daemons, cron, build pipelines,
 * containers without a console) get a pure pass-through with zero overhead.
 * The explicit WHY_DENIED_DISABLE env var provides an escape hatch.
 * ---------------------------------------------------------------------- */
__attribute__((constructor)) static void why_denied_init(void)
{
    /* Stay completely inert in a secure-execution context (setuid/setgid, file
     * capabilities, AT_SECURE). Even though this library only ever reads, a
     * preload installed via /etc/ld.so.preload would otherwise run our probing
     * syscalls and write to STDERR inside privileged programs; refuse that.
     * getauxval(AT_SECURE) is the kernel's authoritative signal here. */
    if (getauxval(AT_SECURE) != 0)
        g_disabled = 1;
    if (!isatty(STDERR_FILENO))
        g_disabled = 1;
    if (getenv("WHY_DENIED_DISABLE") != NULL)
        g_disabled = 1;
}
