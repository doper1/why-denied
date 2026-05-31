#!/usr/bin/env bash
#
# test_denied.sh — behavioural test suite for why-denied.
#
# why-denied only activates when STDERR is a TTY (see why_denied_init() in
# src/why-denied.c), so every probe command is executed inside a pseudo-terminal
# — via util-linux `script`, or a `python3` pty fallback — and we grep the
# captured output for the exact "[why-denied] ..." substring the C code emits.
#
# All probe commands run as the CURRENT (ideally non-root) user, because root
# bypasses every POSIX permission check and would mask the denials we want to
# observe. Cases that need to forge ownership (group-write, sticky-bit,
# chmod-by-non-owner, ACL) use passwordless `sudo` for SETUP only and self-skip
# with a clear message when sudo (or a required tool) is unavailable. GitHub
# Actions runners and the bundled Docker images both provide passwordless sudo.
#
# Triage branches covered automatically here:
#   STANDARD POSIX
#     * missing owner read permission                          (non-root)
#     * missing execute/search permission on a directory       (non-root)
#     * missing owner write permission                         (non-root)
#     * parent dir not writable for create (mkdir)             (non-root)
#     * parent dir not writable for delete (unlink)            (non-root)
#     * missing execute bit for execve                         (non-root)
#     * missing group write permission                         (sudo setup)
#     * sticky-bit directory unlink denial                     (sudo setup)
#     * chmod by non-owner                                     (sudo setup)
#   ACL
#     * extended ACL denial despite permissive POSIX bits      (sudo + setfacl)
#
# Intentionally NOT covered here (host-kernel / policy dependent — needs a
# dedicated enforcing VM, see README "Testing"):
#   * Mandatory Access Control (SELinux / AppArmor)
#   * Network filesystem (NFS/CIFS/SMB) root-squash
#
# Exit status is non-zero if any non-skipped assertion fails.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SO="${WHY_DENIED_SO:-${ROOT}/why-denied.so}"

PASS=0
FAIL=0
SKIP=0

if [ -t 1 ]; then
    c_green=$'\033[0;32m'; c_red=$'\033[0;31m'; c_yellow=$'\033[0;33m'; c_reset=$'\033[0m'
else
    c_green=''; c_red=''; c_yellow=''; c_reset=''
fi

# --------------------------------------------------------------------------
# Build the library if it is not already present.
# --------------------------------------------------------------------------
if [ ! -f "${SO}" ]; then
    echo "Building why-denied.so..."
    make -C "${ROOT}" all || { echo "build failed"; exit 1; }
fi

# --------------------------------------------------------------------------
# Pick a pty driver: util-linux `script` (preferred) or a python3 fallback.
# --------------------------------------------------------------------------
PTY_TOOL=""
if command -v script >/dev/null 2>&1; then
    PTY_TOOL="script"
elif command -v python3 >/dev/null 2>&1; then
    PTY_TOOL="python"
else
    echo "Neither 'script' (util-linux) nor 'python3' is available; cannot drive a pty." >&2
    exit 1
fi

WORK="$(mktemp -d)"
if [ -z "${WORK}" ] || [ ! -d "${WORK}" ]; then
    echo "error: mktemp -d failed to create a work directory" >&2
    exit 1
fi
cleanup() {
    # Some fixtures are root-owned (sudo setup); remove them with sudo too.
    rm -rf "${WORK}" 2>/dev/null || true
    if [ -d "${WORK}" ] && command -v sudo >/dev/null 2>&1; then
        sudo -n rm -rf "${WORK}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Run a command string inside a pty (so STDERR is a TTY) with why-denied
# preloaded, and echo the combined output.
run_under_tty() {
    local cmd="$1"
    local cap; cap="$(mktemp)"
    if [ "${PTY_TOOL}" = "script" ]; then
        # -q (quiet); -c CMD; OUTFILE. We omit -e on purpose: its only effect is
        # to propagate the child's exit code, which we ignore (assertions are on
        # captured output), and this keeps the call compatible with both
        # util-linux and busybox `script` (Alpine/musl).
        script -qc "LD_PRELOAD='${SO}' ${cmd}" "${cap}" >/dev/null 2>&1 || true
    else
        python3 "${ROOT}/tests/pty_run.py" "LD_PRELOAD='${SO}' ${cmd}" "${cap}" >/dev/null 2>&1 || true
    fi
    cat "${cap}"
    rm -f "${cap}"
}

assert_contains() {
    local name="$1" needle="$2" haystack="$3"
    if printf '%s' "${haystack}" | grep -qF -- "${needle}"; then
        printf '%s[PASS]%s %s\n' "${c_green}" "${c_reset}" "${name}"
        PASS=$((PASS + 1))
    else
        printf '%s[FAIL]%s %s\n' "${c_red}" "${c_reset}" "${name}"
        printf '       expected substring: %s\n' "${needle}"
        printf '       actual output:\n%s\n' "${haystack}" | sed 's/^/         /'
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local name="$1" needle="$2" haystack="$3"
    if printf '%s' "${haystack}" | grep -qF -- "${needle}"; then
        printf '%s[FAIL]%s %s\n' "${c_red}" "${c_reset}" "${name}"
        printf '       did NOT expect substring: %s\n' "${needle}"
        printf '       actual output:\n%s\n' "${haystack}" | sed 's/^/         /'
        FAIL=$((FAIL + 1))
    else
        printf '%s[PASS]%s %s\n' "${c_green}" "${c_reset}" "${name}"
        PASS=$((PASS + 1))
    fi
}

skip() {
    printf '%s[SKIP]%s %s\n' "${c_yellow}" "${c_reset}" "$1"
    SKIP=$((SKIP + 1))
}

is_root() { [ "$(id -u)" -eq 0 ]; }

have_sudo() {
    # Non-interactive sudo only (no password prompt). Root needs no sudo.
    is_root || sudo -n true 2>/dev/null
}

# A handful of POSIX cases assert that the CURRENT user is denied. Running them
# as root is meaningless (root bypasses the checks), so they self-skip.
require_nonroot() {
    if is_root; then
        skip "$1 (skipped: running as root bypasses POSIX checks — run as a normal user)"
        return 1
    fi
    return 0
}

echo "why-denied test suite"
echo "  library : ${SO}"
echo "  pty     : ${PTY_TOOL}"
echo "  user    : $(id -un 2>/dev/null || id -u) (uid $(id -u))"
echo "  sudo    : $(have_sudo && echo yes || echo no)"
echo

# ==========================================================================
# STANDARD POSIX — runnable as an ordinary unprivileged user.
# ==========================================================================

# --------------------------------------------------------------------------
# Case 1: missing owner read permission
# --------------------------------------------------------------------------
if require_nonroot "missing owner read permission"; then
    f="${WORK}/noread.txt"
    echo secret > "${f}"
    chmod 000 "${f}"
    out="$(run_under_tty "cat '${f}'")"
    assert_contains "missing owner read permission" "Missing owner read permission" "${out}"
    chmod 600 "${f}"
fi

# --------------------------------------------------------------------------
# Case 2: missing execute (search) permission on a directory
# --------------------------------------------------------------------------
if require_nonroot "missing execute (search) permission on directory"; then
    d="${WORK}/nosearch"
    mkdir -p "${d}"
    echo hi > "${d}/inner.txt"
    chmod 000 "${d}"
    out="$(run_under_tty "cat '${d}/inner.txt'")"
    assert_contains "missing execute (search) permission on directory" "execute (search) permission" "${out}"
    chmod 700 "${d}" # restore so cleanup works
fi

# --------------------------------------------------------------------------
# Case 3: missing owner write permission
# --------------------------------------------------------------------------
if require_nonroot "missing owner write permission"; then
    f="${WORK}/nowrite.txt"
    echo data > "${f}"
    chmod 0444 "${f}"
    out="$(run_under_tty "sh -c \"echo more > '${f}'\"")"
    assert_contains "missing owner write permission" "Missing owner write permission" "${out}"
    chmod 0644 "${f}"
fi

# --------------------------------------------------------------------------
# Case 4: parent directory not writable for create (mkdir)
# --------------------------------------------------------------------------
if require_nonroot "parent dir not writable for create"; then
    pd="${WORK}/ro_parent_create"
    mkdir -p "${pd}"
    chmod 0555 "${pd}" # r-x: searchable but not writable
    out="$(run_under_tty "mkdir '${pd}/child'")"
    assert_contains "parent dir not writable for create" "write into directory" "${out}"
    chmod 0755 "${pd}"
fi

# --------------------------------------------------------------------------
# Case 5: parent directory not writable for delete (unlink)
# --------------------------------------------------------------------------
if require_nonroot "parent dir not writable for delete"; then
    pd="${WORK}/ro_parent_delete"
    mkdir -p "${pd}"
    echo doomed > "${pd}/victim.txt"
    chmod 0555 "${pd}" # r-x: cannot remove an entry
    out="$(run_under_tty "rm -f '${pd}/victim.txt'")"
    assert_contains "parent dir not writable for delete" "write into directory" "${out}"
    chmod 0755 "${pd}"
fi

# --------------------------------------------------------------------------
# Case 6: missing execute bit for execve
# --------------------------------------------------------------------------
if require_nonroot "missing execute bit for execve"; then
    bin="${WORK}/noexec_bit"
    cp /bin/true "${bin}" 2>/dev/null || printf '#!/bin/sh\ntrue\n' > "${bin}"
    chmod 0644 "${bin}" # valid binary, but no execute bit
    # Run the exec from inside a preloaded shell: the failing execve must occur
    # in a process that has why-denied loaded. (A bare "'${bin}'" would be
    # exec'd by the outer, un-preloaded shell that only sets LD_PRELOAD for its
    # children, so the denial would go unseen — unlike a real interactive shell,
    # which is itself preloaded via profile.d.)
    out="$(run_under_tty "sh -c \"'${bin}'\"")"
    assert_contains "missing execute bit for execve" "Missing owner execute permission" "${out}"
fi

# --------------------------------------------------------------------------
# Case 6b: create a NEW file in a read-only directory
#   Distinct code path from the mkdir case: open(O_CREAT) on a missing file in
#   a non-writable parent surfaces as ENOENT, routing through the
#   parent-writable check rather than AK_CREATE.
# --------------------------------------------------------------------------
if require_nonroot "create file in read-only directory"; then
    rd="${WORK}/ro_create_file"
    mkdir -p "${rd}"
    chmod 0555 "${rd}" # r-x: searchable but not writable
    out="$(run_under_tty "sh -c \"echo x > '${rd}/newfile.txt'\"")"
    assert_contains "create file in read-only directory" "write into directory" "${out}"
    chmod 0755 "${rd}"
fi

# --------------------------------------------------------------------------
# Case 6c: rmdir an entry from a read-only parent
#   Exercises the rmdir() wrapper specifically (Case 5 only covers unlink).
# --------------------------------------------------------------------------
if require_nonroot "rmdir in read-only parent"; then
    pd="${WORK}/ro_parent_rmdir"
    mkdir -p "${pd}/victim_dir"
    chmod 0555 "${pd}" # r-x: cannot remove an entry
    out="$(run_under_tty "rmdir '${pd}/victim_dir'")"
    assert_contains "rmdir in read-only parent" "write into directory" "${out}"
    chmod 0755 "${pd}"
fi

# --------------------------------------------------------------------------
# Case 6d: search denial on a deep ANCESTOR (not the leaf)
#   Validates that the ancestor walk reports the first unsearchable directory
#   on the path, not the final component.
# --------------------------------------------------------------------------
if require_nonroot "deep ancestor search denial"; then
    base="${WORK}/deep"
    mkdir -p "${base}/mid/leaf"
    echo hi > "${base}/mid/leaf/file.txt"
    chmod 000 "${base}" # block at the top ancestor
    out="$(run_under_tty "cat '${base}/mid/leaf/file.txt'")"
    assert_contains "deep ancestor search denial (reports first blocker)" "directory '${base}'" "${out}"
    chmod 0755 "${base}"
fi

# ==========================================================================
# STANDARD POSIX — require sudo for SETUP (forging foreign ownership).
# The probe itself still runs as the current unprivileged user.
# ==========================================================================

# --------------------------------------------------------------------------
# Case 7: missing group write permission
#   Owner = nobody, group = our primary group, mode 0705 (group has no write).
#   We fall into the GROUP class, so the kernel denies our write.
# --------------------------------------------------------------------------
if require_nonroot "missing group write permission"; then
    if have_sudo && id nobody >/dev/null 2>&1; then
        gf="${WORK}/groupwrite.txt"
        grp="$(id -gn)"
        echo shared > "${gf}"
        if sudo -n chown "nobody:${grp}" "${gf}" 2>/dev/null \
            && sudo -n chmod 0705 "${gf}" 2>/dev/null \
            && [ "$(stat -c '%U' "${gf}" 2>/dev/null)" = "nobody" ]; then
            out="$(run_under_tty "sh -c \"echo x > '${gf}'\"")"
            assert_contains "missing group write permission" "Missing group write permission" "${out}"
        else
            skip "missing group write permission (could not chown fixture to nobody)"
        fi
        sudo -n rm -f "${gf}" 2>/dev/null || true
    else
        skip "missing group write permission (needs passwordless sudo + 'nobody' user)"
    fi
fi

# --------------------------------------------------------------------------
# Case 8: sticky-bit directory unlink denial
#   The sticky directory MUST be root-owned: a directory's owner may always
#   remove entries, so a user-owned sticky dir would never produce the denial.
# --------------------------------------------------------------------------
if require_nonroot "sticky-bit unlink denial"; then
    if have_sudo; then
        sdir="${WORK}/sticky"
        if sudo -n mkdir -p "${sdir}" 2>/dev/null \
            && sudo -n chmod 1777 "${sdir}" 2>/dev/null \
            && sudo -n sh -c "echo owned-by-root > '${sdir}/rootfile'" 2>/dev/null; then
            out="$(run_under_tty "rm -f '${sdir}/rootfile'")"
            assert_contains "sticky-bit unlink denial" "sticky bit" "${out}"
        else
            skip "sticky-bit unlink denial (could not create root-owned sticky fixture)"
        fi
    else
        skip "sticky-bit unlink denial (needs passwordless sudo)"
    fi
fi

# --------------------------------------------------------------------------
# Case 9: chmod by non-owner
#   A root-owned file we do not own: chmod must fail with EPERM.
# --------------------------------------------------------------------------
if require_nonroot "chmod by non-owner"; then
    if have_sudo; then
        rf="${WORK}/rootowned.txt"
        if sudo -n sh -c "echo root-owned > '${rf}'" 2>/dev/null \
            && [ "$(stat -c '%U' "${rf}" 2>/dev/null)" = "root" ]; then
            out="$(run_under_tty "chmod 600 '${rf}'")"
            assert_contains "chmod by non-owner" "You are not the owner" "${out}"
        else
            skip "chmod by non-owner (could not create root-owned fixture)"
        fi
    else
        skip "chmod by non-owner (needs passwordless sudo)"
    fi
fi

# --------------------------------------------------------------------------
# Case 10: "other"-class read denial carries the world-exposure warning
#   Root-owned file, mode 0640: we are neither owner nor in root's group, so we
#   fall into the OTHER class. The only mode-bit fix (chmod o+r) would grant
#   read to every user, so the suggestion must be flagged accordingly.
# --------------------------------------------------------------------------
if require_nonroot "missing other read permission"; then
    if have_sudo; then
        of="${WORK}/other_read.txt"
        if sudo -n sh -c "echo top > '${of}'" 2>/dev/null \
            && sudo -n chmod 0640 "${of}" 2>/dev/null \
            && [ "$(stat -c '%U' "${of}" 2>/dev/null)" = "root" ]; then
            out="$(run_under_tty "cat '${of}'")"
            assert_contains "missing other read permission" "Missing other read permission" "${out}"
            assert_contains "other read carries world-exposure warning" "grants read access to ALL users" "${out}"
        else
            skip "missing other read permission (could not create root-owned fixture)"
        fi
        sudo -n rm -f "${of}" 2>/dev/null || true
    else
        skip "missing other read permission (needs passwordless sudo)"
    fi
fi

# --------------------------------------------------------------------------
# Case 11: "other"-class directory-search denial carries the warning
#   Root-owned directory, mode 0750: OTHER has no search bit. The suggested
#   'chmod o+x' is flagged because it opens traversal to everyone.
# --------------------------------------------------------------------------
if require_nonroot "missing other search permission"; then
    if have_sudo; then
        od="${WORK}/other_dir"
        if sudo -n mkdir -p "${od}" 2>/dev/null \
            && sudo -n sh -c "echo hi > '${od}/inner.txt'" 2>/dev/null \
            && sudo -n chmod 0750 "${od}" 2>/dev/null \
            && [ "$(stat -c '%U' "${od}" 2>/dev/null)" = "root" ]; then
            out="$(run_under_tty "cat '${od}/inner.txt'")"
            assert_contains "missing other search permission" "execute (search) permission" "${out}"
            assert_contains "other search carries world-exposure warning" "grants search access to ALL users" "${out}"
        else
            skip "missing other search permission (could not create root-owned fixture)"
        fi
        sudo -n rm -rf "${od}" 2>/dev/null || true
    else
        skip "missing other search permission (needs passwordless sudo)"
    fi
fi

# ==========================================================================
# ACL — extended ACL denial despite permissive POSIX bits.
#   File owned by root, mode 0644 (POSIX 'other' grants read), plus a named-user
#   ACL entry denying THIS user. We are not the owner and not in root's group,
#   so why-denied's POSIX math clears us via the 'other' bits and escalates to
#   the ACL branch — which detects the extended (named-user) entry.
# ==========================================================================
if require_nonroot "extended ACL denial"; then
    if have_sudo && command -v setfacl >/dev/null 2>&1; then
        af="${WORK}/acl.txt"
        uid="$(id -u)"
        if sudo -n sh -c "echo acl-protected > '${af}'" 2>/dev/null \
            && sudo -n chmod 0644 "${af}" 2>/dev/null \
            && sudo -n setfacl -m "u:${uid}:---" "${af}" 2>/dev/null \
            && getfacl -nc -- "${af}" 2>/dev/null | grep -q "user:${uid}:"; then
            out="$(run_under_tty "cat '${af}'")"
            assert_contains "extended ACL denial" "Extended Access Control List (ACLs)" "${out}"
        else
            skip "extended ACL denial (filesystem may not support ACLs here)"
        fi
        sudo -n rm -f "${af}" 2>/dev/null || true
    else
        skip "extended ACL denial (needs passwordless sudo + setfacl/getfacl)"
    fi
fi

# ==========================================================================
# SHIM GATING / SAFETY — the library must stay silent unless it should speak.
# ==========================================================================

# --------------------------------------------------------------------------
# Case 12: no output on a successful access (no false positives)
#   The hot path must do nothing at all when a call succeeds.
# --------------------------------------------------------------------------
sf="${WORK}/ok.txt"
echo fine > "${sf}"
chmod 0644 "${sf}"
out="$(run_under_tty "cat '${sf}'")"
assert_not_contains "silent on a successful access" "[why-denied]" "${out}"

# --------------------------------------------------------------------------
# Case 13: WHY_DENIED_DISABLE silences the shim even on a real denial
# --------------------------------------------------------------------------
if require_nonroot "WHY_DENIED_DISABLE escape hatch"; then
    df="${WORK}/disabled.txt"
    echo secret > "${df}"
    chmod 000 "${df}"
    out="$(run_under_tty "WHY_DENIED_DISABLE=1 cat '${df}'")"
    assert_not_contains "WHY_DENIED_DISABLE suppresses output" "[why-denied]" "${out}"
    chmod 600 "${df}"
fi

# --------------------------------------------------------------------------
# Case 14: no output when STDERR is not a TTY (non-interactive contexts)
#   Here we deliberately run WITHOUT a pty and redirect stderr to a pipe, so
#   the load-time isatty() gate disables the library.
# --------------------------------------------------------------------------
if require_nonroot "silent when STDERR is not a TTY"; then
    nf="${WORK}/notty.txt"
    echo secret > "${nf}"
    chmod 000 "${nf}"
    out="$(LD_PRELOAD="${SO}" cat "${nf}" 2>&1 || true)"
    assert_not_contains "silent when STDERR is not a TTY" "[why-denied]" "${out}"
    chmod 600 "${nf}"
fi

# ==========================================================================
# Summary
# ==========================================================================
echo
echo "----------------------------------------"
printf 'why-denied tests: %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
    "${c_green}" "${PASS}" "${c_reset}" \
    "${c_red}" "${FAIL}" "${c_reset}" \
    "${c_yellow}" "${SKIP}" "${c_reset}"
echo "----------------------------------------"

[ "${FAIL}" -eq 0 ]
