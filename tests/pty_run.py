#!/usr/bin/env python3
#
# pty_run.py — minimal pseudo-terminal runner used by test_denied.sh.
#
# why-denied only engages when STDERR is a TTY, so the test suite has to drive
# the probe commands behind a real pty. util-linux `script` is the primary
# vehicle; this helper is the portable fallback for environments (notably some
# musl/Alpine images) where `script` is missing or behaves differently.
#
# Usage:  pty_run.py "<shell command>" "<capture file>"
#
# The command is run via /bin/sh -c under a freshly-allocated pty and every byte
# the child writes (stdout and stderr are merged onto the pty) is appended to
# the capture file. The child's exit status is intentionally ignored: the test
# harness asserts on captured output, not on exit codes.

import os
import pty
import sys


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: pty_run.py <command> <capfile>\n")
        return 2

    cmd = sys.argv[1]
    cap = sys.argv[2]

    with open(cap, "wb") as f:
        def read(fd: int) -> bytes:
            data = os.read(fd, 4096)
            f.write(data)
            f.flush()
            return data

        # pty.spawn returns the child's wait status; we deliberately discard it.
        pty.spawn(["/bin/sh", "-c", cmd], read)

    return 0


if __name__ == "__main__":
    sys.exit(main())
