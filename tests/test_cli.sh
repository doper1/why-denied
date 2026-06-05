#!/usr/bin/env bash
#
# test_cli.sh — behavioural tests for the why-denied CLI.
#
# Exercises bin/why-denied without requiring a system install. Uses WHY_DENIED_SO
# for the dev-tree .so and WHY_DENIED_CLI for the script under test. Service /
# global scope tests write into a temporary WHY_DENIED_CLI_ROOT prefix instead
# of /etc.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SO="${WHY_DENIED_SO:-${ROOT}/why-denied.so}"
CLI="${WHY_DENIED_CLI:-${ROOT}/bin/why-denied}"

PASS=0
FAIL=0

if [ -t 1 ]; then
    c_green=$'\033[0;32m'; c_red=$'\033[0;31m'; c_reset=$'\033[0m'
else
    c_green=''; c_red=''; c_reset=''
fi

if [ ! -f "${SO}" ]; then
    make -C "${ROOT}" all || { echo "build failed"; exit 1; }
fi

if [ ! -x "${CLI}" ]; then
    chmod +x "${CLI}"
fi

PTY_TOOL=""
if command -v script >/dev/null 2>&1; then
    PTY_TOOL="script"
elif command -v python3 >/dev/null 2>&1; then
    PTY_TOOL="python"
else
    echo "Neither 'script' nor 'python3' is available; cannot drive a pty." >&2
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

run_under_tty() {
    local cmd="$1"
    local cap; cap="$(mktemp)"
    if [ "${PTY_TOOL}" = "script" ]; then
        script -qc "${cmd}" "${cap}" >/dev/null 2>&1 || true
    else
        python3 "${ROOT}/tests/pty_run.py" "${cmd}" "${cap}" >/dev/null 2>&1 || true
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
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local name="$1" needle="$2" haystack="$3"
    if printf '%s' "${haystack}" | grep -qF -- "${needle}"; then
        printf '%s[FAIL]%s %s\n' "${c_red}" "${c_reset}" "${name}"
        FAIL=$((FAIL + 1))
    else
        printf '%s[PASS]%s %s\n' "${c_green}" "${c_reset}" "${name}"
        PASS=$((PASS + 1))
    fi
}

assert_exit() {
    local name="$1" expected="$2"
    shift 2
    if "$@"; then
        rc=0
    else
        rc=$?
    fi
    if [ "${rc}" -eq "${expected}" ]; then
        printf '%s[PASS]%s %s\n' "${c_green}" "${c_reset}" "${name}"
        PASS=$((PASS + 1))
    else
        printf '%s[FAIL]%s %s (expected exit %d, got %d)\n' \
            "${c_red}" "${c_reset}" "${name}" "${expected}" "${rc}"
        FAIL=$((FAIL + 1))
    fi
}

# --------------------------------------------------------------------------
# -h / --help / help
# --------------------------------------------------------------------------
for flag in help -h --help; do
    out="$(env WHY_DENIED_SO="${SO}" "${CLI}" "${flag}")"
    assert_contains "${flag} prints usage" "usage: why-denied" "${out}"
done

# --------------------------------------------------------------------------
# status exits successfully
# --------------------------------------------------------------------------
assert_exit "status exits 0" 0 \
    env WHY_DENIED_SO="${SO}" "${CLI}" status >/dev/null

out="$(env WHY_DENIED_SO="${SO}" "${CLI}" status)"
assert_contains "status reports library path" "${SO}" "${out}"

# --------------------------------------------------------------------------
# run under a PTY emits [why-denied] on a real denial
# --------------------------------------------------------------------------
nf="${WORK}/cli-notty.txt"
echo secret > "${nf}"
chmod 000 "${nf}"
out="$(run_under_tty "WHY_DENIED_SO='${SO}' '${CLI}' run cat '${nf}'")"
assert_contains "run emits [why-denied] under a PTY" "[why-denied]" "${out}"
chmod 600 "${nf}"

# --------------------------------------------------------------------------
# run without a PTY still emits when WHY_DENIED_ENABLE is set by the CLI
# --------------------------------------------------------------------------
nf="${WORK}/cli-enable.txt"
echo secret > "${nf}"
chmod 000 "${nf}"
out="$(env WHY_DENIED_SO="${SO}" "${CLI}" run cat "${nf}" 2>&1 || true)"
assert_contains "run enables non-TTY diagnostics" "[why-denied]" "${out}"
chmod 600 "${nf}"

# --------------------------------------------------------------------------
# WHY_DENIED_DISABLE suppresses CLI run output
# --------------------------------------------------------------------------
nf="${WORK}/cli-disable.txt"
echo secret > "${nf}"
chmod 000 "${nf}"
out="$(run_under_tty "WHY_DENIED_SO='${SO}' WHY_DENIED_DISABLE=1 '${CLI}' run cat '${nf}'")"
assert_not_contains "WHY_DENIED_DISABLE suppresses CLI run" "[why-denied]" "${out}"
chmod 600 "${nf}"

# --------------------------------------------------------------------------
# try is shorthand for run cat
# --------------------------------------------------------------------------
nf="${WORK}/cli-try.txt"
echo secret > "${nf}"
chmod 000 "${nf}"
out="$(run_under_tty "WHY_DENIED_SO='${SO}' '${CLI}' try '${nf}'")"
assert_contains "try emits [why-denied]" "[why-denied]" "${out}"
chmod 600 "${nf}"

# --------------------------------------------------------------------------
# enable/disable session print eval-able exports
# --------------------------------------------------------------------------
en_out="$(env WHY_DENIED_SO="${SO}" "${CLI}" enable session 2>/dev/null)"
assert_contains "enable session exports LD_PRELOAD" "export LD_PRELOAD=" "${en_out}"
assert_contains "enable session exports WHY_DENIED_ENABLE" "export WHY_DENIED_ENABLE=1" "${en_out}"

dis_out="$(env WHY_DENIED_SO="${SO}" bash -c "eval \"\$(WHY_DENIED_CLI='${CLI}' WHY_DENIED_SO='${SO}' '${CLI}' enable session 2>/dev/null)\"; WHY_DENIED_CLI='${CLI}' WHY_DENIED_SO='${SO}' '${CLI}' disable session 2>/dev/null")"
assert_contains "disable session unsets WHY_DENIED_ENABLE" "unset WHY_DENIED_ENABLE" "${dis_out}"

# --------------------------------------------------------------------------
# service + global scopes write/remove files under a test prefix
# --------------------------------------------------------------------------
CLI_ROOT="${WORK}/fakeroot"
export WHY_DENIED_CLI_ROOT="${CLI_ROOT}"

env WHY_DENIED_SO="${SO}" WHY_DENIED_CLI_ROOT="${CLI_ROOT}" "${CLI}" enable service >/dev/null
dropin="${CLI_ROOT}/etc/systemd/system.conf.d/why-denied.conf"
if [ -f "${dropin}" ]; then
    printf '%s[PASS]%s enable service writes drop-in\n' "${c_green}" "${c_reset}"
    PASS=$((PASS + 1))
    assert_contains "drop-in sets LD_PRELOAD" "DefaultEnvironment=LD_PRELOAD=" "$(cat "${dropin}")"
    assert_contains "drop-in sets WHY_DENIED_ENABLE" "WHY_DENIED_ENABLE=1" "$(cat "${dropin}")"
else
    printf '%s[FAIL]%s enable service writes drop-in\n' "${c_red}" "${c_reset}"
    FAIL=$((FAIL + 1))
fi

env WHY_DENIED_SO="${SO}" WHY_DENIED_CLI_ROOT="${CLI_ROOT}" "${CLI}" disable service >/dev/null
if [ ! -f "${dropin}" ]; then
    printf '%s[PASS]%s disable service removes drop-in\n' "${c_green}" "${c_reset}"
    PASS=$((PASS + 1))
else
    printf '%s[FAIL]%s disable service removes drop-in\n' "${c_red}" "${c_reset}"
    FAIL=$((FAIL + 1))
fi

env WHY_DENIED_SO="${SO}" WHY_DENIED_CLI_ROOT="${CLI_ROOT}" "${CLI}" enable global >/dev/null
marker="${CLI_ROOT}/etc/why-denied/service-mode"
if [ -f "${marker}" ]; then
    printf '%s[PASS]%s enable global writes service-mode marker\n' "${c_green}" "${c_reset}"
    PASS=$((PASS + 1))
else
    printf '%s[FAIL]%s enable global writes service-mode marker\n' "${c_red}" "${c_reset}"
    FAIL=$((FAIL + 1))
fi

env WHY_DENIED_SO="${SO}" WHY_DENIED_CLI_ROOT="${CLI_ROOT}" "${CLI}" disable global >/dev/null
if [ ! -f "${marker}" ]; then
    printf '%s[PASS]%s disable global removes service-mode marker\n' "${c_green}" "${c_reset}"
    PASS=$((PASS + 1))
else
    printf '%s[FAIL]%s disable global removes service-mode marker\n' "${c_red}" "${c_reset}"
    FAIL=$((FAIL + 1))
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo
echo "----------------------------------------"
printf 'why-denied CLI tests: %s%d passed%s, %s%d failed%s\n' \
    "${c_green}" "${PASS}" "${c_reset}" \
    "${c_red}" "${FAIL}" "${c_reset}"
echo "----------------------------------------"

[ "${FAIL}" -eq 0 ]
