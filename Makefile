# why-denied — build, install, test and packaging.
#
# The core artifact is a position-independent shared object loaded via
# LD_PRELOAD. ACL-based triage is compiled in by default (HAVE_LIBACL=1) and
# linked against libacl; set HAVE_LIBACL=0 to drop that dependency.

CC      ?= cc
PREFIX  ?= /usr
LIBDIR  ?= $(PREFIX)/lib/why-denied
PROFILED ?= /etc/profile.d

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

.PHONY: all clean install uninstall test packages format lint

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Install the shared library and the interactive-session profile hook.
install: $(TARGET)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	install -d $(DESTDIR)$(PROFILED)
	install -m 0644 profile.d/why-denied.sh $(DESTDIR)$(PROFILED)/why-denied.sh
	@echo "Installed. Open a new interactive shell or 'source $(PROFILED)/why-denied.sh'."

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(TARGET)
	rm -f $(DESTDIR)$(PROFILED)/why-denied.sh
	-rmdir $(DESTDIR)$(LIBDIR) 2>/dev/null || true

test: $(TARGET)
	WHY_DENIED_SO="$(CURDIR)/$(TARGET)" bash tests/test_denied.sh

packages: $(TARGET)
	./packager.sh all

format:
	clang-format -i $(SRC)

lint:
	cppcheck --enable=warning,performance,portability --error-exitcode=1 \
	         --suppress=missingIncludeSystem $(SRC)

clean:
	rm -f $(TARGET)
	rm -rf dist
