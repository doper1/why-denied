# Changelog

All notable changes to this project are documented here. This file is
maintained automatically by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/).

## [0.1.1](https://github.com/doper1/why-denied/compare/why-denied-v0.1.0...why-denied-v0.1.1) (2026-05-31)


### Bug Fixes

* mount on shell ([20a3277](https://github.com/doper1/why-denied/commit/20a327784dc37d017d17492349122200fd9d2ee9))

## 0.1.0 (2026-05-31)

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


### Bug Fixes

* redundent pipeline setting ([74ca65e](https://github.com/doper1/why-denied/commit/74ca65e4556768eca8f7d93689312143d12ebc21))


### Miscellaneous Chores

* release 0.1.0 ([81b457e](https://github.com/doper1/why-denied/commit/81b457eaa2ab589f5403df1ae45c6ec788caafc6))
