/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.bpf.c holds Scope kernel-side programs (CO-RE, libbpf).
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
 * Filter gate. One module shared by every program. Each check is a small
 * predicate so the gate reads the same at every attach point. The sampling
 * dice roll lives here only, so enter and exit can never disagree on it.
 */
static __always_inline bool pid_match(__u32 a, __u32 b, __u32 target)
{
	if (!target)
		return true;
	return a == target || b == target;
}

static __always_inline bool cgroup_match(struct scope_config *cfg)
{
	if (!cfg->target_cgroup_id)
		return true;
	return bpf_get_current_cgroup_id() == cfg->target_cgroup_id;
}

static __always_inline bool self_ok(__u32 tgid, struct scope_config *cfg)
{
	/* Never trace ourselves: every emitted event is itself a stdout
	 * write, which would re-enter this pipeline and flood the ringbuf
	 * in a feedback loop (seen in practice: gigabytes in seconds). */
	if (!cfg->self_pid)
		return true;
	return tgid != cfg->self_pid;
}

static __always_inline bool sample_ok(struct scope_config *cfg)
{
	if (cfg->sample_rate <= 1)
		return true;
	return bpf_get_prandom_u32() % cfg->sample_rate == 0;
}

/*
 * The ctx type is the kernel's own `struct trace_event_raw_sched_process_exec`
 * from vmlinux.h. This is deliberate: CO-RE relocates types matched BY NAME
 * against kernel BTF, so a renamed local struct (even layout-identical)
 * fails relocation at load. Lesson learned from verifier output.
 *
 * `__data_loc_filename` packs (len << 16 | offset): the string lives at
 * (void *)ctx + (data_loc & 0xffff). Resolved manually per the trace ABI,
 * no guessing at pointer semantics.
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
		if (!pid_match(pid, ppid, cfg->target_pid))
			return 0;
		have_ppid = true;
	}

	if (!cgroup_match(cfg))
		return 0;

	if (!self_ok(pid, cfg))
		return 0;

	if (!sample_ok(cfg))
		return 0;

	/* Drops the event under backpressure instead of blocking. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

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

	BPF_CORE_READ_INTO(&data_loc, ctx, __data_loc_filename);
	fname = (const char *)ctx + (data_loc & 0xffff);
	if (bpf_probe_read_kernel_str(&e->data.exec.filename,
				     sizeof(e->data.exec.filename),
				     fname) < 0)
		e->data.exec.filename[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* LRU so a thread that dies mid-syscall cannot leak entries. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} sys_start SEC(".maps");

/* PERCPU so updates are plain increments on the local CPU.
 * Userspace sums across CPUs on read. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, SCOPE_MAX_SYSCALL_NR);
	__type(key, __u32);
	__type(value, struct sys_hist);
} sys_hist SEC(".maps");

/* Two layers, one per-thread slot:
 *
 *  - syscall layer: the raw_syscalls sys_enter/sys_exit tracepoints
 *    (the same programs that feed the latency histograms). args[0] is the fd for
 *    read/write/pread64/pwrite64, and this ABI is stable on every kernel.
 *    It is deliberately not kprobes on __x64_sys_*: kernel 7.x changed those
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
 *  7.x reads) consumes the slot and emits. The other finds it gone and
 *  stays silent. Exactly one event per sampled op on every kernel. */

enum io_source {
	SCOPE_IO_SRC_SYSCALL = 1,	/* file resolved from fd at exit */
	SCOPE_IO_SRC_VFS = 2,		/* direct struct file * from vfs layer */
};

/* Per-thread I/O start. LRU so a thread that dies inside a syscall/vfs
 * call cannot leak entries. */
struct io_start {
	__u64 ts;
	__u64 file;	/* SCOPE_IO_SRC_VFS: arg0 of vfs_{read,write} */
	__u32 fd;	/* SCOPE_IO_SRC_SYSCALL: fd from the syscall */
	__u32 source;	/* enum io_source */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct io_start);
} io_start SEC(".maps");

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

static __always_inline bool is_io_nr(__u32 nr)
{
	return nr == SCOPE_NR_read || nr == SCOPE_NR_pread64 ||
	       nr == SCOPE_NR_write || nr == SCOPE_NR_pwrite64;
}

static __always_inline __u32 io_kind_of(__u32 nr)
{
	return (nr == SCOPE_NR_read || nr == SCOPE_NR_pread64) ?
		SCOPE_IO_READ : SCOPE_IO_WRITE;
}

/* Shared exit for the sys_exit tracepoint and the vfs kretprobes.
 * Whichever exit gets here first consumes the slot and emits.
 * The other finds the slot gone and stays silent. */
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
		return 0;
	bpf_map_delete_elem(&io_start, &tid);

	/* Errors and EOF move no bytes, so there is nothing to report. */
	if (ret <= 0)
		return 0;

	now = bpf_ktime_get_ns();
	delta = now - st->ts;

	/* Emit rule: with no thresholds active, emit everything.
	 * Otherwise emit when the op crosses at least one active threshold
	 * (slow or big). */
	cfg = bpf_map_lookup_elem(&scope_cfg, &zero);
	if (cfg) {
		bool lat_active = cfg->min_latency_ns != 0;
		bool bytes_active = cfg->min_io_bytes != 0;
		bool lat_missed = delta < cfg->min_latency_ns;
		bool bytes_missed = (__u64)ret < cfg->min_io_bytes;

		if ((lat_active || bytes_active) &&
		    (!lat_active || lat_missed) &&
		    (!bytes_active || bytes_missed))
			return 0;
	}

	file_val = st->source == SCOPE_IO_SRC_VFS ? st->file : fd_to_file(st->fd);
	file = (const struct file *)file_val;

	dentry = NULL;
	name = NULL;
	parent = NULL;
	pname = NULL;
	/* Only the dentry name plus one-hop parent name. Full path
	 * resolution is userspace work. */
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

	if (!pid_match(tid, tgid, cfg->target_pid))
		return 0;

	if (!cgroup_match(cfg))
		return 0;

	if (!self_ok(tgid, cfg))
		return 0;

	if (!sample_ok(cfg))
		return 0;

	BPF_CORE_READ_INTO(&sys_id, ctx, id);
	nr = (__u32)sys_id;

	now = bpf_ktime_get_ns();
	bpf_map_update_elem(&sys_start, &tid, &now, BPF_ANY);

	/* Syscall-layer I/O start. args[0] is the fd for
	 * read/write/pread64/pwrite64. The raw tracepoint ABI carries the
	 * six syscall args directly, stable across all kernels (unlike
	 * kprobes on __x64_sys_*, which switched to a pt_regs * argument
	 * in 7.x and silently corrupted fd reads). */
	if (is_io_nr(nr)) {
		struct io_start st;
		unsigned long fd;

		BPF_CORE_READ_INTO(&fd, ctx, args[0]);
		st.ts = now;
		st.file = 0;
		st.fd = (__u32)fd;
		st.source = SCOPE_IO_SRC_SYSCALL;
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

	BPF_CORE_READ_INTO(&sys_id, ctx, id);
	nr = (__u32)sys_id;

	start = bpf_map_lookup_elem(&sys_start, &tid);
	if (!start) {
		/* Enter never ran (gated out) or its sys_start entry was
		 * evicted: any io_start slot for this tid is stranded
		 * garbage, not this op's. Drop it so the next op cannot
		 * inherit a stale fd. */
		if (is_io_nr(nr))
			bpf_map_delete_elem(&io_start, &tid);
		return 0;
	}
	delta = bpf_ktime_get_ns() - *start;
	bpf_map_delete_elem(&sys_start, &tid);

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
	}
	/* Per-CPU value: plain increments, race-free on this CPU. The
	 * slot index is bounded by the clamp above (verifier-visible).
	 * h == NULL is only reachable under map pressure; skip the
	 * histogram then (never skip the I/O slot consume below, since a
	 * stranded io_start slot would misattribute the next op). */
	if (h) {
		h->slots[slot] += 1;
		h->count += 1;
		h->total_ns += delta;
	}

	/* Syscall-layer I/O exit. The vfs-layer kretprobes (when they fire
	 * on <= 6.x) already consumed the slot; on 7.x reads this
	 * is the only consumer. Always runs for I/O syscalls (see above). */
	if (is_io_nr(nr)) {
		BPF_CORE_READ_INTO(&ret, ctx, ret);
		io_emit(ret, io_kind_of(nr));
	}
	return 0;
}

/* vfs layer: refine an existing syscall-layer slot with the direct file
 * pointer. Presence-driven, so no gate re-roll and no slot creation. */
static __always_inline int io_enter_vfs(struct file *file)
{
	struct io_start *st;
	struct io_start nst;
	__u32 tid;

	tid = (__u32)bpf_get_current_pid_tgid();
	st = bpf_map_lookup_elem(&io_start, &tid);
	if (!st)
		return 0;

	nst.ts = bpf_ktime_get_ns();
	nst.file = (__u64)file;
	nst.fd = st->fd;
	nst.source = SCOPE_IO_SRC_VFS;
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
