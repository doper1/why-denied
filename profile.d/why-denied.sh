# /etc/profile.d/why-denied.sh
#
# Activate the why-denied LD_PRELOAD shim, but ONLY for interactive shells.
#
# Rationale: why-denied is a diagnostic aid for humans. Loading it into
# non-interactive contexts (daemons started by init/systemd, cron jobs, build
# pipelines) is undesirable — it adds a (tiny) cost to process startup and is
# pointless when no human is watching stderr. The `[ -t 1 ]` test means stdout
# is a terminal, which is a reliable proxy for "a person launched this shell".
#
# We append to any existing LD_PRELOAD rather than overwriting it, preserving
# other preloaded libraries. POSIX sh only — this file is sourced by /bin/sh.

if [ -t 1 ]; then
    LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}/usr/lib/why-denied/why-denied.so"
    export LD_PRELOAD
fi
