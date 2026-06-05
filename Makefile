# why-denied — build, install, test and packaging.
#
# The core artifact is a position-independent shared object loaded via
# LD_PRELOAD. ACL-based triage is compiled in by default (HAVE_LIBACL=1) and
# linked against libacl; set HAVE_LIBACL=0 to drop that dependency.

CC      ?= cc
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
LIBDIR  ?= $(PREFIX)/lib/why-denied
PROFILED ?= /etc/profile.d
CLI     := bin/why-denied
MANPAGE := man/why-denied.1

# Build the ACL backend by default.
HAVE_LIBACL ?= 1

CFLAGS  ?= -O3 -Wall -Wextra -fPIC
LDFLAGS ?= -shared
LDLIBS  := -ldl

ifeq ($(HAVE_LIBACL),1)
CFLAGS  += -DHAVE_LIBACL=1
LDLIBS  += -lacl
endif

SRC    := src/why-denied.c
TARGET := why-denied.so

# Packaging metadata. version.txt is the single source of truth (kept in sync by
# release-please); the source tarball + Arch PKGBUILD derive their version here.
NAME     := why-denied
VERSION  := $(shell tr -d ' \t\r\n' < version.txt)
DISTNAME := $(NAME)-$(VERSION)
DIST     := dist

.PHONY: all clean install uninstall test packages tarball pkgbuild format lint

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Install the shared library, CLI, and the interactive-session profile hook.
install: $(TARGET)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(CLI) $(DESTDIR)$(BINDIR)/why-denied
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man1/why-denied.1
	install -d $(DESTDIR)$(PROFILED)
	install -m 0644 profile.d/why-denied.sh $(DESTDIR)$(PROFILED)/why-denied.sh
	@echo "Installed. Open a new interactive shell, run 'why-denied status', or 'source $(PROFILED)/why-denied.sh'."

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/why-denied
	rm -f $(DESTDIR)$(MANDIR)/man1/why-denied.1
	rm -f $(DESTDIR)$(PROFILED)/why-denied.sh
	-rmdir $(DESTDIR)$(LIBDIR) 2>/dev/null || true

test: $(TARGET)
	WHY_DENIED_SO="$(CURDIR)/$(TARGET)" bash tests/test_denied.sh
	WHY_DENIED_SO="$(CURDIR)/$(TARGET)" WHY_DENIED_CLI="$(CURDIR)/$(CLI)" bash tests/test_cli.sh

packages: $(TARGET)
	./packager.sh all

# Source tarball for from-source installs (and as the PKGBUILD's upstream
# source). Uses `git archive` so the tarball contains exactly the tracked tree,
# prefixed with $(DISTNAME)/ to match GitHub's own tag-archive layout.
tarball:
	@mkdir -p $(DIST)
	git archive --format=tar.gz --prefix=$(DISTNAME)/ \
		-o $(DIST)/$(DISTNAME).tar.gz HEAD
	@echo "Wrote $(DIST)/$(DISTNAME).tar.gz"

# Render the Arch source recipe (AUR-style PKGBUILD) with the current version
# substituted. Arch ships a SOURCE recipe rather than a prebuilt binary: it has
# no native fpm target, and makepkg builds from this on the user's machine.
pkgbuild:
	@mkdir -p $(DIST)
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@NAME@/$(NAME)/g' \
		packaging/PKGBUILD.in > $(DIST)/PKGBUILD
	@echo "Wrote $(DIST)/PKGBUILD (pkgver=$(VERSION))"

format:
	clang-format -i $(SRC)

lint:
	cppcheck --enable=warning,performance,portability --error-exitcode=1 \
	         --suppress=missingIncludeSystem $(SRC)

clean:
	rm -f $(TARGET)
	rm -rf dist
