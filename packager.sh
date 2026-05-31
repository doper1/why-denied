#!/usr/bin/env bash
#
# packager.sh — build native packages (.deb / .rpm / .apk) for why-denied
# using fpm (https://github.com/jordansissel/fpm).
#
# It assembles a staging tree that mirrors the install layout:
#   /usr/lib/why-denied/why-denied.so
#   /etc/profile.d/why-denied.sh
# and then asks fpm to emit one or more package formats from that tree.
#
# Usage:
#   ./packager.sh [deb|rpm|apk|all]      (default: all)
#
# Requirements: fpm, and a compiled why-denied.so (run `make` first, or this
# script will build it for you if the source toolchain is present).

set -euo pipefail

# --------------------------------------------------------------------------
# Configurable metadata (override via environment).
# --------------------------------------------------------------------------
NAME="why-denied"
VERSION="$(tr -d ' \t\r\n' < version.txt 2>/dev/null || echo 0.1.0)"
ARCH="${ARCH:-$(uname -m)}"
MAINTAINER="${MAINTAINER:-why-denied contributors <noreply@example.com>}"
DESCRIPTION="Human-readable root-cause analysis for Permission Denied (EACCES/EPERM) errors."
URL="${URL:-https://github.com/why-denied/why-denied}"
LICENSE="MIT"

ROOT="$(cd "$(dirname "$0")" && pwd)"
STAGE="${ROOT}/dist/stage"
OUT="${ROOT}/dist"
TARGET_SO="${ROOT}/why-denied.so"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Preflight.
# --------------------------------------------------------------------------
command -v fpm >/dev/null 2>&1 || die "fpm is not installed (gem install fpm)."

if [ ! -f "${TARGET_SO}" ]; then
    log "why-denied.so not found — building it."
    make -C "${ROOT}" all
fi

# --------------------------------------------------------------------------
# Build the staging tree.
# --------------------------------------------------------------------------
stage() {
    log "Staging files into ${STAGE}"
    rm -rf "${STAGE}"
    install -d "${STAGE}/usr/lib/why-denied"
    install -m 0644 "${TARGET_SO}" "${STAGE}/usr/lib/why-denied/why-denied.so"
    install -d "${STAGE}/etc/profile.d"
    install -m 0644 "${ROOT}/profile.d/why-denied.sh" \
        "${STAGE}/etc/profile.d/why-denied.sh"
    install -d "${OUT}"
}

# Common fpm arguments shared by every output format.
fpm_common() {
    printf '%s\0' \
        -s dir \
        -n "${NAME}" \
        -v "${VERSION}" \
        -a "${ARCH}" \
        --maintainer "${MAINTAINER}" \
        --description "${DESCRIPTION}" \
        --url "${URL}" \
        --license "${LICENSE}" \
        --vendor "why-denied" \
        -C "${STAGE}"
}

run_fpm() {
    local type="$1"; shift
    log "Building ${type} package"
    # shellcheck disable=SC2046
    mapfile -d '' common < <(fpm_common)
    fpm -t "${type}" "${common[@]}" "$@" -p "${OUT}/" .
}

build_deb() { run_fpm deb --depends libacl1; }
build_rpm() { run_fpm rpm --depends libacl; }
build_apk() { run_fpm apk --depends acl; }

main() {
    local what="${1:-all}"
    stage
    case "${what}" in
        deb) build_deb ;;
        rpm) build_rpm ;;
        apk) build_apk ;;
        all) build_deb; build_rpm; build_apk ;;
        *)   die "unknown target '${what}' (expected deb|rpm|apk|all)" ;;
    esac
    log "Done. Packages written to ${OUT}/"
    ls -1 "${OUT}"/*.deb "${OUT}"/*.rpm "${OUT}"/*.apk 2>/dev/null || true
}

main "$@"
