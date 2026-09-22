/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.bpf.h — shared ABI between BPF kernel programs and userspace.
 *
 * Included by both scope.bpf.c (compiled with -target bpf) and scope.c
 * (normal userspace compile). Must stay POD, fixed-size, and stable:
 * the ringbuf wire format is versioned only by `enum scope_event_type`.
 *
 * NOTE: __u32 etc. come from vmlinux.h on the BPF side; on the userspace
 * side we define them from stdint.h so we don't depend on kernel headers.
 */
#ifndef __SCOPE_BPF_H
#define __SCOPE_BPF_H

#ifndef __BPF__
/* Kernel __u8..__s64 types (also pulled in by the bpftool skeleton
 * via libbpf headers — include it here so we never redefine them). */
#include <linux/types.h>
#endif

#define SCOPE_COMM_LEN     16
#define SCOPE_FILENAME_LEN 256

/* Wire event discriminator. New event kinds are appended in later phases;
 * old values never change meaning. */
enum scope_event_type {
	SCOPE_EVENT_EXEC = 1,	/* struct exec_event (Phase 1) */
	SCOPE_EVENT_EXIT = 2,	/* reserved: Phase 2+ */
	SCOPE_EVENT_IO   = 3,	/* reserved: Phase 3 */
	SCOPE_EVENT_TCP  = 4,	/* reserved: Phase 4 */
};

/*
 * Global in-kernel config, single entry in the scope_cfg ARRAY map.
 * Every BPF program reads this FIRST and returns early on mismatch —
 * cheap early return is the #1 overhead-reduction technique.
 */
struct scope_config {
	__u32 sample_rate;	/* 1 = every event, N = emit ~1-in-N */
	__u32 target_pid;	/* 0 = all PIDs */
	__u32 self_pid;		/* scope's own pid: never traced (feedback) */
	__u32 _pad;
	__u64 target_cgroup_id;	/* 0 = all cgroups */
	__u64 min_latency_ns;	/* I/O latency threshold (-l) */
};

/* SCOPE_EVENT_EXEC payload: one successful exec(). */
struct exec_event {
	__u64 timestamp_ns;	/* bpf_ktime_get_ns() at exec */
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u64 cgroup_id;	/* bpf_get_current_cgroup_id() */
	char comm[SCOPE_COMM_LEN];
	char filename[SCOPE_FILENAME_LEN];
};

/* File I/O direction (Phase 3). */
enum scope_io_kind {
	SCOPE_IO_READ = 1,
	SCOPE_IO_WRITE = 2,
};

/* SCOPE_EVENT_IO payload: one completed vfs_read/vfs_write.
 * Named scope_io_event: vmlinux.h already defines `struct io_event`
 * (aio), and the BPF TU includes both headers. */
struct scope_io_event {
	__u64 timestamp_ns;	/* bpf_ktime_get_ns() at exit */
	__u64 delta_ns;		/* entry -> exit */
	__u32 pid;
	__u32 tid;
	__u32 kind;		/* enum scope_io_kind */
	__u32 fd;		/* fd the op went through (path work aid) */
	__s64 bytes;		/* positive: bytes moved (syscall return) */
	char comm[SCOPE_COMM_LEN];
	char filename[SCOPE_FILENAME_LEN];
	char dirname[SCOPE_FILENAME_LEN]; /* d_parent name, one hop only */
};

/* Syscall latency histogram (Phase 2). One entry per syscall nr in a
 * PERCPU_HASH: pure in-kernel aggregation, zero per-event traffic.
 * Slot s holds samples in [2^(s-1), 2^s) ns; slot 0 holds exact-zero;
 * slot 31 saturates (holds everything >= 2^30 ns). */
#define SCOPE_HIST_SLOTS 32
#define SCOPE_MAX_SYSCALL_NR 512

/* x86_64 syscall numbers (stable ABI) for the I/O syscalls we trace at
 * the raw-syscall layer. vmlinux.h does not define __NR_*. */
#define SCOPE_NR_read      0
#define SCOPE_NR_write     1
#define SCOPE_NR_pread64   17
#define SCOPE_NR_pwrite64  18

struct sys_hist {
	__u64 slots[SCOPE_HIST_SLOTS];
	__u64 count;
	__u64 total_ns;
};

/* Ringbuf envelope. Union grows in later phases. */
struct scope_event {
	__u32 type;		/* enum scope_event_type */
	__u32 _pad;
	union {
		struct exec_event exec;
		struct scope_io_event io;
	} data;
};

#endif /* __SCOPE_BPF_H */
