#!/usr/bin/env bash
#
# docker-test.sh — build + run the why-denied behavioural test suite inside one
# or more distro containers, then print a combined PASS/FAIL summary.
#
# This is a thin, deterministic wrapper around `docker compose` so that the
# local workflow is byte-for-byte identical to what CI runs:
#
#     make && bash tests/test_denied.sh
#
# (executed as an unprivileged user with passwordless sudo, per the images in
# docker/).
#
# Usage:
#   ./docker-test.sh [debian|ubuntu|rocky|rhel|fedora|opensuse|arch|alpine|all]
#
# With NO argument it runs a single, fast, representative distro (debian) — the
# whole 8-image matrix is a cold-build of multiple heavy base images (openSUSE
# alone can take ~1000s+ on a first run) and is really CI-oriented. Run one
# distro locally and reserve `all` for CI / a deliberate full sweep. Exit
# status is non-zero if any selected distro's test suite fails.
#
# Windows: runs as-is from PowerShell or Git Bash with Docker Desktop, e.g.
#   docker compose run --rm test-debian
#   bash docker-test.sh debian
#   bash docker-test.sh all       # slow: builds all 8 distro images

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${ROOT}"

# Resolve the compose CLI (v2 plugin `docker compose`, or legacy `docker-compose`).
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

# Default to a single fast distro; `all` is opt-in (slow, CI-oriented).
target="${1:-debian}"
case "${target}" in
    debian)   services=(test-debian) ;;
    ubuntu)   services=(test-ubuntu) ;;
    rocky)    services=(test-rocky) ;;
    rhel)     services=(test-rhel) ;;
    fedora)   services=(test-fedora) ;;
    opensuse) services=(test-opensuse) ;;
    arch)     services=(test-arch) ;;
    alpine)   services=(test-alpine) ;;
    all)
        services=(test-debian test-ubuntu test-rocky test-rhel test-fedora test-opensuse test-arch test-alpine)
        echo "WARNING: 'all' cold-builds 8 distro images (openSUSE/Arch/Fedora are heavy;" >&2
        echo "         the first run can take many minutes). This is the CI sweep — for" >&2
        echo "         local work prefer a single distro, e.g. '$0 debian'." >&2
        ;;
    *)
        echo "usage: $0 [debian|ubuntu|rocky|rhel|fedora|opensuse|arch|alpine|all]" >&2
        echo "       (no argument runs 'debian'; 'all' runs the full, slow matrix)" >&2
        exit 2
        ;;
esac

declare -a results=()
overall=0

for svc in "${services[@]}"; do
    echo
    echo "========================================================================"
    echo ">>> ${svc}: building image"
    echo "========================================================================"
    "${COMPOSE[@]}" build "${svc}"

    echo
    echo ">>> ${svc}: running 'make && bash tests/test_denied.sh'"
    if "${COMPOSE[@]}" run --rm "${svc}"; then
        results+=("PASS  ${svc}")
    else
        results+=("FAIL  ${svc}")
        overall=1
    fi
done

echo
echo "========================================================================"
echo "Combined distro matrix summary"
echo "========================================================================"
for r in "${results[@]}"; do
    echo "  ${r}"
done
echo "------------------------------------------------------------------------"
if [ "${overall}" -eq 0 ]; then
    echo "All selected distro suites PASSED."
else
    echo "One or more distro suites FAILED."
fi

exit "${overall}"
