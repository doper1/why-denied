# /etc/profile.d/why-denied.sh
#
# Activate the why-denied LD_PRELOAD shim for interactive shells.
#
# Rationale: why-denied is a diagnostic aid for humans. Loading it into
# non-interactive contexts (daemons started by init/systemd, cron jobs, build
# pipelines) is undesirable — it adds a (tiny) cost to process startup and is
# pointless when no human is watching stderr. The `[ -t 1 ]` test means stdout
# is a terminal, which is a reliable proxy for "a person launched this shell".
#
# We append to any existing LD_PRELOAD rather than overwriting it, preserving
# other preloaded libraries. POSIX sh only — this file is sourced by /bin/sh.
#
# Self-instrumentation: LD_PRELOAD is only honored at process startup, so merely
# exporting it here leaves the CURRENT (already-running) shell uninstrumented —
# it would catch external commands like `cat`, but miss failures the shell
# performs directly: failed execs of its own children (`./script`) and its own
# redirections (`echo x > file`). To fix that we export LD_PRELOAD and then
# re-exec the interactive shell once, with a guard variable so we never loop.
# This makes "every interactive shell is preloaded" literally true.

# Only act when stdout is a terminal (a human is present) AND the shared object
# is actually installed. The `-e` guard avoids polluting LD_PRELOAD with a path
# that ld.so cannot find — otherwise a half-removed package (hook present, .so
# gone) would emit an "object not found" warning on EVERY exec.
if [ -t 1 ] && [ -e /usr/lib/why-denied/why-denied.so ]; then
    # Append our path idempotently — the login re-exec below re-sources this
    # file, and we must not grow LD_PRELOAD with a duplicate entry each time.
    case ":${LD_PRELOAD}:" in
        *:/usr/lib/why-denied/why-denied.so:*) ;;
        *) LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}/usr/lib/why-denied/why-denied.so" ;;
    esac
    export LD_PRELOAD

    # Re-exec the interactive shell once so it is itself preloaded. Skipped for
    # non-interactive shells (the `*i*` test), when explicitly disabled, and
    # after the first pass (the guard). We re-exec as a LOGIN shell (`-l`) so the
    # full login sequence (/etc/profile, ~/.profile, ~/.bashrc) runs normally;
    # the guard makes the second pass fall straight through without looping.
    # Descendant shells inherit both LD_PRELOAD and the guard, so they start
    # preloaded without re-exec'ing.
    case "$-" in
        *i*)
            if [ -z "$WHY_DENIED_REEXEC" ] && [ -z "$WHY_DENIED_DISABLE" ]; then
                export WHY_DENIED_REEXEC=1
                if [ -n "$BASH" ]; then
                    exec "$BASH" -l
                elif [ -n "$ZSH_NAME" ]; then
                    exec "$ZSH_NAME" -l
                fi
                # Unknown shell: leave the guard set and fall through. Children
                # are still instrumented; only the shell's own execs are missed.
            fi
            ;;
    esac
fi
