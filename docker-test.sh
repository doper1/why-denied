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
#   ./docker-test.sh [debian|rocky|alpine|all]
#
# With no argument, runs all three. Exit status is non-zero if any selected
# distro's test suite fails.
#
# Windows: runs as-is from PowerShell or Git Bash with Docker Desktop, e.g.
#   docker compose run --rm test-debian
#   bash docker-test.sh all

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

target="${1:-all}"
case "${target}" in
    debian) services=(test-debian) ;;
    rocky)  services=(test-rocky) ;;
    rhel)   services=(test-rhel) ;;
    alpine) services=(test-alpine) ;;
    all)    services=(test-debian test-rocky test-rhel test-alpine) ;;
    *)
        echo "usage: $0 [debian|rocky|rhel|alpine|all]" >&2
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
