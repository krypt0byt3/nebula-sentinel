# bpf/Makefile — compile the Nebula Sentinel CO-RE BPF object.
#
# Output: bpf/nebula.bpf.o  (a single CO-RE object that runs across kernels)
#
# Prerequisites (one-time, on the BUILD host — not every target):
#   - clang/llvm 12+         (apt install clang llvm)
#   - libbpf headers         (apt install libbpf-dev)
#   - bpftool                (apt install linux-tools-common linux-tools-$(uname -r))
#
# vmlinux.h is generated from the build host's BTF. Because we use CO-RE, the
# resulting object relocates correctly on OTHER kernels at load time — you do
# NOT need to rebuild per target kernel.
#
# Usage:
#   make            # generate vmlinux.h (if missing) and build nebula.bpf.o
#   make install    # copy nebula.bpf.o to /usr/lib/nebula/ (the runtime path)
#   make clean

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
# Pick up libbpf headers + our local headers (vmlinux.h, nebula_events.h).
# The Makefile path always generates the FULL vmlinux.h via bpftool, so tell
# nebula.bpf.c to include it (NEBULA_HAVE_FULL_VMLINUX) rather than the minimal
# fallback header (which intentionally omits kernel base types like __wsum,
# struct pt_regs, and the BPF_MAP_TYPE_* enums — those live in vmlinux.h).
CFLAGS += -DNEBULA_HAVE_FULL_VMLINUX -I. -I/usr/include/$(shell uname -m)-linux-gnu

all: nebula.bpf.o

# Generate vmlinux.h from the running kernel's BTF (CO-RE type definitions).
vmlinux.h:
	@echo ">> Generating vmlinux.h from kernel BTF…"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

nebula.bpf.o: nebula.bpf.c nebula_events.h vmlinux.h
	@echo ">> Compiling CO-RE BPF object…"
	$(CLANG) $(CFLAGS) -c nebula.bpf.c -o nebula.bpf.o
	@echo ">> Stripping DWARF (keeping .BTF for CO-RE)…"
	@command -v llvm-strip >/dev/null && llvm-strip -g nebula.bpf.o \
	    || strip -g nebula.bpf.o \
	    || echo "   (no llvm-strip/strip — object may be too large for aya; install llvm)"
	@echo ">> Built $@ — verify sections with: llvm-objdump -h $@"

install: nebula.bpf.o
	install -d /usr/lib/nebula
	install -m 0644 nebula.bpf.o /usr/lib/nebula/nebula.bpf.o
	@echo ">> Installed to /usr/lib/nebula/nebula.bpf.o (the agent's runtime search path)"

clean:
	rm -f nebula.bpf.o

# Keep vmlinux.h out of `clean` — it's slow to regenerate and host-specific.
distclean: clean
	rm -f vmlinux.h

.PHONY: all install clean distclean
