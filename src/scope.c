/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.c loads and attaches the BPF programs, polls the ring buffer,
 * and dumps the syscall histogram once a second. Event formatting
 * lives in output.c. Histogram math lives in histogram.c.
 */
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "bpf/scope.bpf.h"
#include "bpf/scope.skel.h"
#include "histogram.h"
#include "output.h"

static struct {
	__u32 pid;
	char *cgroup_path;
	__u64 cgroup_id;
	__u32 sample_rate;
	__u64 min_latency_ns;
	__u64 min_io_bytes;
	bool json;
	bool verbose;
} opt = {
	.sample_rate = 1,
};

static struct argp_option options[] = {
	{ "pid", 'p', "PID", 0, "Trace only this PID (0 = all)", 0 },
	{ "cgroup", 'c', "PATH", 0, "Trace only this cgroup (cgroupfs path)", 0 },
	{ "sample", 's', "N", 0, "Sample 1-in-N events (default 1 = all)", 0 },
	{ "min-latency", 'l', "USEC", 0,
	  "Only emit I/O events >= this latency", 0 },
	{ "min-bytes", 'b', "BYTES", 0,
	  "Only emit I/O events >= this size", 0 },
	{ "no-ui", 'n', 0, 0, "Stream JSON events, no TUI (same as -o json)", 0 },
	{ "output", 'o', "MODE", 0, "'json' streams JSON lines to stdout", 0 },
	{ "verbose", 'v', 0, 0, "Verbose libbpf output (shows loader/verifier log)", 0 },
	{ 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	(void)state;
	switch (key) {
	case 'p':
		opt.pid = (unsigned)strtoul(arg, NULL, 0);
		break;
	case 'c':
		opt.cgroup_path = arg;
		break;
	case 's':
		opt.sample_rate = (unsigned)strtoul(arg, NULL, 0);
		if (opt.sample_rate == 0)
			opt.sample_rate = 1;
		break;
	case 'l':
		opt.min_latency_ns = strtoull(arg, NULL, 0) * 1000ULL;
		break;
	case 'b':
		opt.min_io_bytes = strtoull(arg, NULL, 0);
		break;
	case 'n':
		opt.json = true;
		break;
	case 'o':
		if (strcmp(arg, "json") == 0) {
			opt.json = true;
		} else {
			fprintf(stderr, "unknown output mode '%s' (want 'json')\n", arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'v':
		opt.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {
	.options = options,
	.parser = parse_opt,
	.doc = "Scope, eBPF-based Linux observability tool.\n",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !opt.verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct scope_event *ev = data;
	(void)ctx;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "truncated event (%zu bytes), dropped\n", len);
		return 0;
	}
	if (output_event(ev, opt.json) != 0)
		fprintf(stderr, "unknown event type %u, dropped\n", ev->type);
	fflush(stdout);
	return 0;
}

/* Reads the live histogram map (the prod adapter) and hands plain
 * snapshots to the histogram module. Tests feed recorded snapshots
 * to the same interface without touching the kernel. */
static void dump_syscalls(struct scope_bpf *skel, bool json,
			  struct timespec *tick, struct timespec *now)
{
	static struct sys_hist prev[SCOPE_MAX_SYSCALL_NR];
	static bool have_prev;
	struct sys_row rows[SCOPE_MAX_SYSCALL_NR];
	struct sys_row *order[SCOPE_MAX_SYSCALL_NR];
	int map_fd = bpf_map__fd(skel->maps.sys_hist);
	int ncpus = libbpf_num_possible_cpus();
	size_t vsize = bpf_map__value_size(skel->maps.sys_hist);
	size_t pbuf_sz = hist_percpu_stride(vsize) * ncpus;
	char *pbuf = malloc(pbuf_sz);
	__u64 grand_count = 0, grand_total = 0;
	double dt;
	int n = 0, keys_done = 0;
	__u32 key = 0, next;

	if (!pbuf || ncpus <= 0 || vsize < sizeof(struct sys_hist)) {
		free(pbuf);
		return;
	}

	while (keys_done++ < SCOPE_MAX_SYSCALL_NR &&
	       bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		struct sys_hist cur;

		key = next;
		if (bpf_map_lookup_elem(map_fd, &key, pbuf) != 0)
			continue;
		hist_sum_percpu(pbuf, ncpus, vsize, &cur);

		if (key < SCOPE_MAX_SYSCALL_NR) {
			struct sys_row *r = &rows[n++];

			hist_diff_row(key, &cur, &prev[key], have_prev, r);
			grand_count += r->delta.count;
			grand_total += r->delta.total_ns;
		}
		prev[key] = cur;
	}
	have_prev = true;
	free(pbuf);

	dt = (double)(now->tv_sec - tick->tv_sec) +
	     (double)(now->tv_nsec - tick->tv_nsec) / 1e9;
	if (dt <= 0)
		dt = 1.0;

	for (int i = 0; i < n; i++)
		order[i] = &rows[i];
	qsort(order, n, sizeof(order[0]), hist_row_cmp);
	if (n > HIST_TOP_N)
		n = HIST_TOP_N;

	output_syscalls(order, n, dt, grand_count, grand_total, json);
}

int main(int argc, char **argv)
{
	struct scope_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct scope_config cfg = {};
	const __u32 zero = 0;
	struct timespec tick, now;
	int err;

	if (argp_parse(&argp, argc, argv, 0, NULL, NULL))
		return 1;

	/* Resolve cgroup path -> cgroup id (kernfs inode number, which is
	 * what bpf_get_current_cgroup_id() returns). */
	if (opt.cgroup_path) {
		struct stat st;
		if (stat(opt.cgroup_path, &st) < 0) {
			fprintf(stderr, "stat(%s): %s\n", opt.cgroup_path,
				strerror(errno));
			return 1;
		}
		opt.cgroup_id = (uint64_t)st.st_ino;
		fprintf(stderr, "filter: cgroup %s -> id %llu\n",
			opt.cgroup_path, (unsigned long long)opt.cgroup_id);
	}

	libbpf_set_print(libbpf_print_fn);

	skel = scope_bpf__open();
	if (!skel) {
		fprintf(stderr, "scope_bpf__open failed\n");
		return 1;
	}

	if (scope_bpf__load(skel)) {
		fprintf(stderr, "scope_bpf__load failed\n");
		err = 1;
		goto out;
	}

	cfg.sample_rate = opt.sample_rate;
	cfg.target_pid = opt.pid;
	cfg.self_pid = (__u32)getpid();
	cfg.target_cgroup_id = opt.cgroup_id;
	cfg.min_latency_ns = opt.min_latency_ns;
	cfg.min_io_bytes = opt.min_io_bytes;
	if (bpf_map__update_elem(skel->maps.scope_cfg, &zero, sizeof(zero),
				 &cfg, sizeof(cfg), BPF_ANY)) {
		fprintf(stderr, "config map update failed: %s\n", strerror(errno));
		err = 1;
		goto out;
	}

	if (scope_bpf__attach(skel)) {
		fprintf(stderr, "scope_bpf__attach failed\n");
		err = 1;
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno));
		err = 1;
		goto out;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR ||
	    signal(SIGTERM, sig_handler) == SIG_ERR) {
		fprintf(stderr, "signal setup failed\n");
		err = 1;
		goto out;
	}

	if (!opt.json) {
		fprintf(stderr,
			"scope: tracing exec + syscalls + file I/O "
			"(pid=%u sample=1-in-%u). Ctrl-C to stop.\n",
			opt.pid, opt.sample_rate);
	}

	/* 20 ms poll timeout keeps shutdown responsive without busy looping.
	 * The histogram dump rides the same loop on a 1 s tick, so no extra
	 * thread or timer signal is needed. */
	clock_gettime(CLOCK_MONOTONIC, &tick);
	while (!stop) {
		err = ring_buffer__poll(rb, 20);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n",
				strerror(-err));
			err = 1;
			goto out;
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - tick.tv_sec >= 1) {
			dump_syscalls(skel, opt.json, &tick, &now);
			tick = now;
			fflush(stdout);
		}
	}
	err = 0;
out:
	ring_buffer__free(rb);
	scope_bpf__destroy(skel);
	return err;
}
