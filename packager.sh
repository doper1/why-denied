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
# version.txt is the single source of truth (kept in sync by release-please).
# Fail hard rather than silently shipping a wrong/stale version.
VERSION="$(tr -d ' \t\r\n' < version.txt)" \
    || { printf 'error: cannot read version.txt\n' >&2; exit 1; }
[ -n "${VERSION}" ] || { printf 'error: version.txt is empty\n' >&2; exit 1; }
ARCH="${ARCH:-$(uname -m)}"
# GitHub no-reply form by default; override with MAINTAINER=... for a real one.
MAINTAINER="${MAINTAINER:-why-denied contributors <doper1@users.noreply.github.com>}"
DESCRIPTION="Human-readable root-cause analysis for Permission Denied (EACCES/EPERM) errors."
URL="${URL:-https://github.com/doper1/why-denied}"
LICENSE="MIT"

# Optional tag appended to the output package FILENAME (not the package
# metadata). We package by FORMAT + libc + libacl-variant rather than per
# distro, because the compiled artifact is identical within those axes — so the
# tag encodes that axis (e.g. "glibc", "glibc-noacl", "musl"), producing names
# like why-denied_0.1.1_amd64-glibc.deb. Empty => keep fpm's default name.
# Renaming only affects the asset name, never the package contents.
PKG_TAG="${PKG_TAG:-}"
# RPM runtime dependency. Defaults to the libacl SONAME capability, which
# resolves on every glibc RPM family (RHEL/Rocky/Fedora ship `libacl`, openSUSE
# ships `libacl5`, but all PROVIDE `libacl.so.1()(64bit)`). Set RPM_DEPENDS=none
# for the libacl-free build (HAVE_LIBACL=0, e.g. RHEL/UBI which has no
# libacl-devel): that variant detects ACLs via xattr and links no libacl, so it
# must NOT carry a libacl dependency.
RPM_DEPENDS="${RPM_DEPENDS:-libacl.so.1()(64bit)}"

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

# Append PKG_TAG to the basename of every freshly built package of extension
# $1 (the fpm type doubles as the file extension for deb/rpm/apk). Idempotent:
# files already carrying the tag are skipped. No-op when PKG_TAG is empty.
tag_output() {
    local ext="$1" f base
    [ -n "${PKG_TAG}" ] || return 0
    for f in "${OUT}"/*."${ext}"; do
        [ -e "${f}" ] || continue
        case "${f}" in
            *"-${PKG_TAG}.${ext}") continue ;;
        esac
        base="${f%.${ext}}"
        mv -f "${f}" "${base}-${PKG_TAG}.${ext}"
        log "Tagged package -> $(basename "${base}-${PKG_TAG}.${ext}")"
    done
}

run_fpm() {
    local type="$1"; shift
    log "Building ${type} package"
    # shellcheck disable=SC2046
    mapfile -d '' common < <(fpm_common)
    fpm -t "${type}" "${common[@]}" "$@" -p "${OUT}/" .
    tag_output "${type}"
}

build_deb() { run_fpm deb --depends libacl1; }
# Depend on the SONAME capability rather than a package name: the RPM families
# disagree on the package name (RHEL/Rocky/Fedora ship `libacl`, openSUSE ships
# `libacl5`), but they all PROVIDE `libacl.so.1()(64bit)`, so this one dependency
# resolves everywhere. (64-bit targets only; our ARCH is x86_64/aarch64.)
# RPM_DEPENDS=none drops the dependency for the libacl-free HAVE_LIBACL=0 build.
build_rpm() {
    if [ "${RPM_DEPENDS}" = "none" ] || [ -z "${RPM_DEPENDS}" ]; then
        run_fpm rpm
    else
        run_fpm rpm --depends "${RPM_DEPENDS}"
    fi
}
# On Alpine the shared library lives in the `libacl` package; `acl` is just the
# setfacl/getfacl tools. why-denied.so links libacl.so.1, so depend on `libacl`.
build_apk() { run_fpm apk --depends libacl; }

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
