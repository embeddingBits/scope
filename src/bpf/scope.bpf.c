/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.bpf.c — Scope's kernel-side programs (CO-RE, libbpf).
 *
 * Phase 1: sched_process_exec tracepoint -> ringbuf. Later phases append
 * syscall, I/O and TCP programs to this file (or split it once it grows).
 *
 * CO-RE rules followed throughout:
 *  - all kernel struct access via BPF_CORE_READ* (never direct deref),
 *  - config-map early return before any work,
 *  - bounded strings via bpf_probe_read_kernel_str into fixed buffers.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "scope.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Primary event channel: single ringbuf, 256 KiB. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Global config, index 0. Written by userspace before attach. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scope_config);
} scope_cfg SEC(".maps");

/*
 * The ctx type is the kernel's own `struct trace_event_raw_sched_process_exec`
 * from vmlinux.h. This is deliberate: CO-RE relocates types matched BY NAME
 * against kernel BTF, so a renamed local struct (even layout-identical)
 * fails relocation at load. Lesson learned from verifier output.
 *
 * `__data_loc_filename` packs (len << 16 | offset): the string lives at
 * (void *)ctx + (data_loc & 0xffff). Resolved manually — exact per the
 * trace ABI, no guessing at pointer semantics.
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	const __u32 zero = 0;
	struct scope_config *cfg;
	struct scope_event *e;
	struct task_struct *task, *parent;
	const char *fname;
	__u32 data_loc, ppid = 0;
	bool have_ppid = false;
	__u64 pid_tgid, uid_gid;
	__u32 pid;

	/* 1. Config check first: cheapest possible filter. */
	cfg = bpf_map_lookup_elem(&scope_cfg, &zero);
	if (!cfg)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	if (cfg->target_pid) {
		struct task_struct *ftask =
			(struct task_struct *)bpf_get_current_task_btf();
		struct task_struct *fparent;

		BPF_CORE_READ_INTO(&fparent, ftask, real_parent);
		if (fparent)
			BPF_CORE_READ_INTO(&ppid, fparent, tgid);
		if (pid != cfg->target_pid && ppid != cfg->target_pid)
			return 0;
		have_ppid = true;
	}

	if (cfg->target_cgroup_id) {
		__u64 cg = bpf_get_current_cgroup_id();

		if (cg != cfg->target_cgroup_id)
			return 0;
	}

	if (cfg->sample_rate > 1) {
		if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
			return 0;
	}

	/* 2. Reserve ringbuf space (drop on pressure, never block). */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	/* 3. Fill the event. */
	e->type = SCOPE_EVENT_EXEC;
	e->_pad = 0;
	e->data.exec.timestamp_ns = bpf_ktime_get_ns();
	e->data.exec.pid = pid;
	e->data.exec.cgroup_id = bpf_get_current_cgroup_id();

	uid_gid = bpf_get_current_uid_gid();
	e->data.exec.uid = (__u32)uid_gid;
	e->data.exec.gid = (__u32)(uid_gid >> 32);

	/* PPID via task->real_parent->tgid, NULL-guarded. Skipped when the
	 * PID filter already resolved it above. */
	if (!have_ppid) {
		task = (struct task_struct *)bpf_get_current_task_btf();
		BPF_CORE_READ_INTO(&parent, task, real_parent);
		if (parent)
			BPF_CORE_READ_INTO(&ppid, parent, tgid);
	}
	e->data.exec.ppid = ppid;

	bpf_get_current_comm(&e->data.exec.comm, sizeof(e->data.exec.comm));

	/* Filename from the __data_loc offset. */
	BPF_CORE_READ_INTO(&data_loc, ctx, __data_loc_filename);
	fname = (const char *)ctx + (data_loc & 0xffff);
	if (bpf_probe_read_kernel_str(&e->data.exec.filename,
				     sizeof(e->data.exec.filename),
				     fname) < 0)
		e->data.exec.filename[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Per-thread syscall start times, keyed by tid. LRU so a thread that
 * dies inside a syscall cannot leak entries and evict live ones. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} sys_start SEC(".maps");

/* Per-syscall log2 latency histograms. PERCPU: updates are plain
 * increments on the local CPU, no atomics, no cross-CPU traffic;
 * userspace sums across CPUs on read. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, SCOPE_MAX_SYSCALL_NR);
	__type(key, __u32);
	__type(value, struct sys_hist);
} sys_hist SEC(".maps");

/* ---- Phase 3: file I/O infrastructure (maps + helpers used by the
 * raw_syscalls programs above and the vfs kprobes below) ---- */

/* Two layers, one per-thread slot:
 *
 *  - syscall layer: the raw_syscalls sys_enter/sys_exit tracepoints
 *    (same programs as the Phase 2 histograms). args[0] is the fd for
 *    read/write/pread64/pwrite64, and this ABI is stable on every kernel
 *    — deliberately NOT kprobes on __x64_sys_*: kernel 7.x changed those
 *    functions to take `struct pt_regs *` instead of expanded args (BTF
 *    on 7.2.2: FUNC_PROTO '__x64_sys_pread64' vlen=1 'regs'), so an
 *    arg0-based fd read silently yields the regs pointer there.
 *
 *  - vfs layer: kprobe/kretprobe on vfs_read/vfs_write. On <= 6.x these
 *    fire inside the syscall and overwrite the slot with the direct
 *    struct file * (tighter latency: vfs entry -> vfs exit). On 7.x the
 *    read syscall path dispatches straight to f_op->read_iter and never
 *    enters vfs_read (verified via function_graph on 7.2.2), so this
 *    layer stays silent there and the syscall layer emits.
 *
 *  Dedup: the sampling/filter gate lives ONLY in the syscall-layer
 *  entry. A vfs entry fires only if a syscall-layer entry created the
 *  slot (lookup-first, no second dice roll), then overwrites it. Whichever
 *  exit fires first (the inner vfs one on <= 6.x, the syscall one on
 *  7.x reads) consumes the slot and emits — the other finds it gone and
 *  stays silent. Exactly one event per sampled op on every kernel. */

enum io_source {
	IO_SRC_SYSCALL = 1,	/* file resolved from fd at exit */
	IO_SRC_VFS = 2,		/* direct struct file * from vfs layer */
};

/* Per-thread I/O start. LRU so a thread that dies inside a syscall/vfs
 * call cannot leak entries. */
struct io_start {
	__u64 ts;
	__u64 file;	/* IO_SRC_VFS: arg0 of vfs_{read,write} */
	__u32 fd;	/* IO_SRC_SYSCALL: fd from the syscall */
	__u32 source;	/* enum io_source */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct io_start);
} io_start SEC(".maps");

/* Resolve struct file * from an fd: current->files->fdt->fd[fd]. */
static __always_inline __u64 fd_to_file(unsigned int fd)
{
	struct task_struct *task;
	struct files_struct *files;
	struct file **fdarr;
	struct file *file = NULL;
	unsigned int max_fds;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;
	BPF_CORE_READ_INTO(&files, task, files);
	if (!files)
		return 0;
	BPF_CORE_READ_INTO(&fdarr, files, fdt, fd);
	if (!fdarr)
		return 0;
	BPF_CORE_READ_INTO(&max_fds, files, fdt, max_fds);
	if (fd >= max_fds)
		return 0;
	bpf_probe_read_kernel(&file, sizeof(file), fdarr + fd);
	return (__u64)file;
}

/* Exit side (shared by the sys_exit tracepoint and the vfs kretprobes):
 * consume the slot, resolve the file (direct or via fd), apply the -l
 * latency threshold, emit. Whichever exit gets here first wins; the
 * other finds the slot gone. */
static __always_inline int io_emit(long ret, __u32 kind)
{
	struct io_start *st;
	struct scope_config *cfg;
	struct scope_event *e;
	const struct file *file;
	const struct dentry *dentry, *parent;
	const unsigned char *name, *pname;
	const __u32 zero = 0;
	__u64 pid_tgid, now, delta, file_val;
	__u32 tid;

	tid = (__u32)bpf_get_current_pid_tgid();
	st = bpf_map_lookup_elem(&io_start, &tid);
	if (!st)
		return 0; /* gated, or the inner vfs exit already consumed */
	bpf_map_delete_elem(&io_start, &tid);

	if (ret <= 0)
		return 0; /* errors/EOF carry no bytes */

	now = bpf_ktime_get_ns();
	delta = now - st->ts;

	/* -l MIN_LATENCY_US: only slow I/O crosses to userspace. */
	cfg = bpf_map_lookup_elem(&scope_cfg, &zero);
	if (cfg && cfg->min_latency_ns && delta < cfg->min_latency_ns)
		return 0;

	file_val = st->source == IO_SRC_VFS ? st->file : fd_to_file(st->fd);
	file = (const struct file *)file_val;

	dentry = NULL;
	name = NULL;
	parent = NULL;
	pname = NULL;
	/* CO-RE chains; probe_read-based, NULL-checked after each hop.
	 * Deliberately shallow: dentry name + one-hop parent name; full
	 * path resolution is userspace work (later phases). */
	if (file) {
		BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
		if (dentry) {
			BPF_CORE_READ_INTO(&name, dentry, d_name.name);
			BPF_CORE_READ_INTO(&parent, dentry, d_parent);
			if (parent)
				BPF_CORE_READ_INTO(&pname, parent,
						   d_name.name);
		}
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = SCOPE_EVENT_IO;
	e->_pad = 0;
	pid_tgid = bpf_get_current_pid_tgid();
	e->data.io.timestamp_ns = now;
	e->data.io.delta_ns = delta;
	e->data.io.pid = (__u32)(pid_tgid >> 32);
	e->data.io.tid = tid;
	e->data.io.kind = kind;
	e->data.io.fd = st->fd;
	e->data.io.bytes = ret;

	bpf_get_current_comm(&e->data.io.comm, sizeof(e->data.io.comm));
	if (name)
		bpf_probe_read_kernel_str(&e->data.io.filename,
					 sizeof(e->data.io.filename), name);
	else
		e->data.io.filename[0] = '\0';
	if (pname)
		bpf_probe_read_kernel_str(&e->data.io.dirname,
					 sizeof(e->data.io.dirname), pname);
	else
		e->data.io.dirname[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	const __u32 zero = 0;
	struct scope_config *cfg;
	__u64 pid_tgid, now;
	__u32 tid, tgid;
	long sys_id;
	__u32 nr;

	cfg = bpf_map_lookup_elem(&scope_cfg, &zero);
	if (!cfg)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	tgid = (__u32)(pid_tgid >> 32);

	/* Match tid OR tgid: one -p flag covers all threads of a process. */
	if (cfg->target_pid && tid != cfg->target_pid &&
	    tgid != cfg->target_pid)
		return 0;

	if (cfg->target_cgroup_id &&
	    bpf_get_current_cgroup_id() != cfg->target_cgroup_id)
		return 0;

	/* Never trace ourselves: every emitted event is itself a stdout
	 * write, which would re-enter this pipeline and flood the ringbuf
	 * in a feedback loop (seen in practice: 7.5 GB in seconds). */
	if (cfg->self_pid && tgid == cfg->self_pid)
		return 0;

	/* The sampling gate lives ONLY here. Exit is driven by the presence
	 * of a start entry, so enter/exit can never disagree on the
	 * decision — no torn samples, no map leaks from skipped exits. */
	if (cfg->sample_rate > 1 &&
	    bpf_get_prandom_u32() % cfg->sample_rate != 0)
		return 0;

	BPF_CORE_READ_INTO(&sys_id, ctx, id);
	nr = (__u32)sys_id;

	now = bpf_ktime_get_ns();
	bpf_map_update_elem(&sys_start, &tid, &now, BPF_ANY);

	/* Phase 3: syscall-layer I/O start. args[0] is the fd for
	 * read/write/pread64/pwrite64 — the raw tracepoint ABI carries the
	 * six syscall args directly, stable across all kernels (unlike
	 * kprobes on __x64_sys_*, which switched to a pt_regs * argument
	 * in 7.x and silently corrupted fd reads). */
	if (nr == SCOPE_NR_read || nr == SCOPE_NR_pread64 ||
	    nr == SCOPE_NR_write || nr == SCOPE_NR_pwrite64) {
		struct io_start st;
		unsigned long fd;

		BPF_CORE_READ_INTO(&fd, ctx, args[0]);
		st.ts = now;
		st.file = 0;
		st.fd = (__u32)fd;
		st.source = IO_SRC_SYSCALL;
		bpf_map_update_elem(&io_start, &tid, &st, BPF_ANY);
	}
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct sys_hist zero = { 0 };
	struct sys_hist *h;
	__u64 *start, delta;
	long sys_id, ret;
	__u32 tid, nr, slot;

	tid = (__u32)bpf_get_current_pid_tgid();
	start = bpf_map_lookup_elem(&sys_start, &tid);
	if (!start)
		return 0; /* unsampled, filtered, or enter lost to eviction */
	delta = bpf_ktime_get_ns() - *start;
	bpf_map_delete_elem(&sys_start, &tid);

	BPF_CORE_READ_INTO(&sys_id, ctx, id);
	nr = (__u32)sys_id;
	if (nr >= SCOPE_MAX_SYSCALL_NR)
		return 0;

	if (delta == 0) {
		slot = 0;
	} else {
		slot = 64 - __builtin_clzll(delta);
		if (slot > SCOPE_HIST_SLOTS - 1)
			slot = SCOPE_HIST_SLOTS - 1;
	}

	h = bpf_map_lookup_elem(&sys_hist, &nr);
	if (!h) {
		bpf_map_update_elem(&sys_hist, &nr, &zero, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&sys_hist, &nr);
		if (!h)
			return 0;
	}
	/* Per-CPU value: plain increments, race-free on this CPU. The
	 * slot index is bounded by the clamp above (verifier-visible). */
	h->slots[slot] += 1;
	h->count += 1;
	h->total_ns += delta;

	/* Phase 3: syscall-layer I/O exit. The vfs-layer kretprobes (when
	 * they fire — <= 6.x) already consumed the slot; on 7.x reads this
	 * is the only consumer. */
	if (nr == SCOPE_NR_read || nr == SCOPE_NR_pread64) {
		BPF_CORE_READ_INTO(&ret, ctx, ret);
		io_emit(ret, SCOPE_IO_READ);
	} else if (nr == SCOPE_NR_write || nr == SCOPE_NR_pwrite64) {
		BPF_CORE_READ_INTO(&ret, ctx, ret);
		io_emit(ret, SCOPE_IO_WRITE);
	}
	return 0;
}

/* vfs layer: refine an existing syscall-layer slot with the direct file
 * pointer. Presence-driven — no gate re-roll, no slot creation. */
static __always_inline int io_enter_vfs(struct file *file)
{
	struct io_start *st;
	struct io_start nst;
	__u32 tid;

	tid = (__u32)bpf_get_current_pid_tgid();
	st = bpf_map_lookup_elem(&io_start, &tid);
	if (!st)
		return 0; /* gated out at syscall layer (or layer absent) */

	nst.ts = bpf_ktime_get_ns();
	nst.file = (__u64)file;
	nst.fd = st->fd;
	nst.source = IO_SRC_VFS;
	bpf_map_update_elem(&io_start, &tid, &nst, BPF_ANY);
	return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(handle_vfs_read, struct file *file)
{
	return io_enter_vfs(file);
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(handle_vfs_read_ret, ssize_t ret)
{
	return io_emit(ret, SCOPE_IO_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(handle_vfs_write, struct file *file)
{
	return io_enter_vfs(file);
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(handle_vfs_write_ret, ssize_t ret)
{
	return io_emit(ret, SCOPE_IO_WRITE);
}
