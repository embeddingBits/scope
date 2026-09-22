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
