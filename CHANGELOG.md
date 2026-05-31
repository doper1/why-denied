# Changelog

All notable changes to this project are documented here. This file is
maintained automatically by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/).

## 0.1.0 (2026-05-31)


### Miscellaneous Chores

* release 0.1.0 ([81b457e](https://github.com/doper1/why-denied/commit/81b457eaa2ab589f5403df1ae45c6ec788caafc6))

## 0.1.0 (2026-01-01)

### Features

* LD_PRELOAD interception of file, exec, directory and attribute syscalls
  (`open`, `openat`, `creat`, `execve`, `execveat`, `mkdir`, `mkdirat`,
  `rmdir`, `unlink`, `unlinkat`, `chmod`, `fchmod`, `fchmodat`, `chown`,
  `fchown`, `fchownat`).
* Human-readable root-cause analysis for `EACCES`/`EPERM` failures with exact
  `chmod` remediations.
* Advanced triage fallback: POSIX ACLs, network filesystems (NFS/CIFS/SMB) and
  Mandatory Access Control (SELinux/AppArmor).
* Interactive-session-only activation via TTY detection and the
  `/etc/profile.d` hook.
* Cross-distro packaging (`.deb`, `.rpm`, `.apk`) via fpm.
