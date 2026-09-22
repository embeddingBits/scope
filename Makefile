# Scope — Makefile
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
USER_SRC  := src/scope.c
BIN       := scope

# uname -m -> __TARGET_ARCH_* mapping for the BPF compile.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  BPF_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
  BPF_ARCH := arm
else ifeq ($(UNAME_M),riscv64)
  BPF_ARCH := riscv
else ifeq ($(UNAME_M),ppc64le)
  BPF_ARCH := powerpc
else ifeq ($(UNAME_M),s390x)
  BPF_ARCH := s390
else
  $(error unsupported arch for BPF build: $(UNAME_M))
endif

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
	@echo "clang:    $$(clang --version | head -1)"
	@echo "bpftool:  $$(bpftool version | head -1)"
	@echo "libbpf:   headers present"
	@echo "kernel:   $$(uname -r), BTF present"
	@echo "OK"

$(VMLINUX_H):
	@echo "== generating $@ from running kernel BTF =="
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(VMLINUX_H)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX_H)
	@echo "== clang $@ =="
	clang $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

$(SKEL_H): $(BPF_OBJ)
	@echo "== bpftool gen skeleton $@ =="
	bpftool gen skeleton $(BPF_OBJ) > $@

$(BIN): $(USER_SRC) $(SKEL_H) $(BPF_HDR)
	@echo "== gcc $@ =="
	gcc -g -O2 -Wall -Wextra -Isrc -o $(BIN) $(USER_SRC) -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(VMLINUX_H) $(BIN)
