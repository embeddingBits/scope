# Scope Makefile
#
# Targets:
#   deps     check build prerequisites
#   vmlinux  generate src/bpf/vmlinux.h from the running kernel's BTF
#   build    vmlinux + BPF object + skeleton + userspace binary (default)
#   clean    remove generated files and the binary

BPF_DIR   := src/bpf
BPF_SRC   := $(BPF_DIR)/scope.bpf.c
BPF_HDR   := $(BPF_DIR)/scope.bpf.h
BPF_OBJ   := $(BPF_DIR)/scope.bpf.o
VMLINUX_H := $(BPF_DIR)/vmlinux.h
SKEL_H    := $(BPF_DIR)/scope.skel.h
USER_SRC  := src/scope.c src/output.c src/histogram.c
USER_HDR  := src/output.h src/histogram.h
SYSNAMES_H := src/syscall_names.h
SYSCALL_HDR := /usr/include/asm/unistd_64.h
BIN       := scope

# x86_64 only, by decision. No multi-arch mapping.
UNAME_M := $(shell uname -m)
ifneq ($(UNAME_M),x86_64)
  $(error scope supports x86_64 only (got $(UNAME_M)))
endif
BPF_ARCH := x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	      -I$(BPF_DIR) -Wall -Wno-missing-declarations

.PHONY: all build deps vmlinux clean
all: build
build: $(BIN)

deps:
	@echo "== checking prerequisites =="
	@command -v clang >/dev/null   || { echo "MISSING: clang"; exit 1; }
	@command -v bpftool >/dev/null || { echo "MISSING: bpftool"; exit 1; }
	@command -v gcc >/dev/null     || { echo "MISSING: gcc"; exit 1; }
	@test -f /usr/include/bpf/libbpf.h || test -f /usr/local/include/bpf/libbpf.h \
		|| { echo "MISSING: libbpf headers (install libbpf-dev / libbpf)"; exit 1; }
	@test -f /sys/kernel/btf/vmlinux \
		|| { echo "MISSING: /sys/kernel/btf/vmlinux (need CONFIG_DEBUG_INFO_BTF)"; exit 1; }
	@test -f $(SYSCALL_HDR) \
		|| { echo "MISSING: $(SYSCALL_HDR) (install linux-api-headers)"; exit 1; }
	@echo "clang:    $$(clang --version | head -1)"
	@echo "bpftool:  $$(bpftool version | head -1)"
	@echo "libbpf:   headers present"
	@echo "kernel:   $$(uname -r), BTF present"
	@echo "OK"

$(VMLINUX_H):
	@echo "== generating $@ from running kernel BTF =="
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(VMLINUX_H)

# x86_64 syscall table is stable kernel ABI (never renumbered); generate the
# name table from the installed kernel-api headers rather than hand-editing.
$(SYSNAMES_H): $(SYSCALL_HDR)
	@echo "== gen $@ =="
	@{ \
		printf '/* SPDX-License-Identifier: GPL-2.0 */\n'; \
		printf '/* Generated from asm/unistd_64.h - x86_64 syscall table (stable ABI). */\n'; \
		printf 'static const char *const syscall_names[] = {\n'; \
		awk '/^#define __NR_/ { printf "\t[%d] = \"%s\",\n", $$3, substr($$2, 6) }' \
			'$(SYSCALL_HDR)'; \
		printf '};\n'; \
	} > $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX_H)
	@echo "== clang $@ =="
	clang $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

$(SKEL_H): $(BPF_OBJ)
	@echo "== bpftool gen skeleton $@ =="
	bpftool gen skeleton $(BPF_OBJ) > $@

$(BIN): $(USER_SRC) $(USER_HDR) $(SKEL_H) $(BPF_HDR) $(SYSNAMES_H)
	@echo "== gcc $@ =="
	gcc -g -O2 -Wall -Wextra -Isrc -o $(BIN) $(USER_SRC) -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(VMLINUX_H) $(SYSNAMES_H) $(BIN)
