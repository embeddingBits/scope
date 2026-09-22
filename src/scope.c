/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.c — Scope userspace: load/attach BPF, poll ringbuf, print events.
 *
 * Phase 1: exec events only, human-readable lines or JSON lines
 * (--no-ui / -o json). Aggregation + TUI arrive in later phases.
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
#include "syscall_names.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* ---- CLI ---- */

static struct {
	__u32 pid;
	char *cgroup_path;
	__u64 cgroup_id;
	__u32 sample_rate;
	__u64 min_latency_ns;
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
	  "Min latency to emit (reserved for I/O + syscall phases)", 0 },
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
	.doc = "Scope — eBPF-based Linux observability tool (Phase 1: exec tracing).\n",
};

/* ---- libbpf logging ---- */

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	/* Always show warnings/errors; debug only with -v (loader/verifier). */
	if (level == LIBBPF_DEBUG && !opt.verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* ---- shutdown ---- */

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
	(void)sig;
	stop = 1;
}

/* ---- output ---- */

/* Minimal JSON string escaper for comm/filename. */
static void json_escape(FILE *f, const char *s, size_t max)
{
	fputc('"', f);
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = (unsigned char)s[i];
		switch (c) {
		case '"': fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f); break;
		case '\t': fputs("\\t", f); break;
		default:
			if (c < 0x20)
				fprintf(f, "\\u%04x", c);
			else
				fputc(c, f);
		}
	}
	fputc('"', f);
}

static void print_human(const struct exec_event *e)
{
	char ts[32];
	time_t sec = (time_t)(e->timestamp_ns / 1000000000ULL);
	struct tm tm;

	localtime_r(&sec, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
	printf("%s.%03llu EXEC pid=%-7u ppid=%-7u uid=%-5u comm=%.16s file=%.256s cgroup=%llu\n",
	       ts, (e->timestamp_ns / 1000000ULL) % 1000ULL,
	       e->pid, e->ppid, e->uid, e->comm, e->filename,
	       (unsigned long long)e->cgroup_id);
}

static void print_json(const struct exec_event *e)
{
	printf("{\"type\":\"exec\",\"ts\":%llu,\"pid\":%u,\"ppid\":%u,"
	       "\"uid\":%u,\"gid\":%u,\"cgroup_id\":%llu,\"comm\":",
	       (unsigned long long)e->timestamp_ns,
	       e->pid, e->ppid, e->uid, e->gid,
	       (unsigned long long)e->cgroup_id);
	json_escape(stdout, e->comm, sizeof(e->comm));
	printf(",\"filename\":");
	json_escape(stdout, e->filename, sizeof(e->filename));
	printf("}\n");
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct scope_event *ev = data;
	(void)ctx;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "truncated event (%zu bytes), dropped\n", len);
		return 0;
	}
	if (ev->type != SCOPE_EVENT_EXEC) {
		fprintf(stderr, "unknown event type %u, dropped\n", ev->type);
		return 0;
	}
	if (opt.json)
		print_json(&ev->data.exec);
	else
		print_human(&ev->data.exec);
	fflush(stdout);
	return 0;
}

/* ---- syscall histogram (Phase 2) ---- */

/* syscalls are in-kernel aggregated into PERCPU_HASH; userspace sums the
 * per-CPU values once per second, diffs against the previous snapshot to
 * get interval rates, and reports percentiles from the slot histograms. */

static const char *syscall_name(__u32 nr)
{
	if (nr < ARRAY_SIZE(syscall_names) && syscall_names[nr])
		return syscall_names[nr];
	/* unknown/unused nr: rotating static buffers (cheap, thread-local
	 * single-threaded context) */
	static char buf[4][16];
	static unsigned idx;
	char *b = buf[idx++ % 4];
	snprintf(b, 16, "sys_%u", nr);
	return b;
}

static void fmt_ns(char *out, size_t n, __u64 ns)
{
	if (ns >= 1000000000ULL)
		snprintf(out, n, "%.2fs", (double)ns / 1e9);
	else if (ns >= 1000000ULL)
		snprintf(out, n, "%.2fms", (double)ns / 1e6);
	else if (ns >= 1000ULL)
		snprintf(out, n, "%.2fus", (double)ns / 1e3);
	else
		snprintf(out, n, "%lluns", (unsigned long long)ns);
}

/* Upper bound of histogram slot s in ns: slot s covers [2^(s-1), 2^s).
 * Slot 0 is exact zero; slot 31 saturates (>= 2^30 ns). */
static __u64 slot_upper_ns(int s)
{
	if (s <= 0)
		return 0;
	return 1ULL << s;
}

static __u64 percentile_ns(const __u64 *slots, __u64 count, double p)
{
	__u64 target, cum = 0;
	int s;

	if (count == 0)
		return 0;
	target = (__u64)((double)count * p);
	if (target == 0)
		target = 1;
	for (s = 0; s < SCOPE_HIST_SLOTS; s++) {
		cum += slots[s];
		if (cum >= target)
			return slot_upper_ns(s);
	}
	return slot_upper_ns(SCOPE_HIST_SLOTS - 1);
}

/* One aggregated syscall row. `d_*` are interval deltas; percentiles are
 * computed on the delta histogram. */
struct sys_row {
	__u32 nr;
	const char *name;
	__u64 d_count;
	__u64 d_total_ns;
	__u64 d_slots[SCOPE_HIST_SLOTS];
	__u64 avg_ns, p50_ns, p90_ns, p99_ns;
};

static int row_cmp(const void *a, const void *b)
{
	const struct sys_row *ra = *(struct sys_row *const *)a;
	const struct sys_row *rb = *(struct sys_row *const *)b;

	if (ra->d_count < rb->d_count)
		return 1;
	if (ra->d_count > rb->d_count)
		return -1;
	return 0;
}

/* Sum one PERCPU_HASH value across CPUs (libbpf lays percpu values out
 * with stride roundup(value_size, 8)). */
static void sum_percpu(const void *vals, int ncpus, size_t vsize,
		       struct sys_hist *out)
{
	size_t stride = (vsize + 7) & ~7UL;

	memset(out, 0, sizeof(*out));
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct sys_hist *h =
			(const struct sys_hist *)((const char *)vals +
						 cpu * stride);
		for (int s = 0; s < SCOPE_HIST_SLOTS; s++)
			out->slots[s] += h->slots[s];
		out->count += h->count;
		out->total_ns += h->total_ns;
	}
}

#define TOP_N 10

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
	size_t pbuf_sz = ((vsize + 7) & ~7UL) * ncpus;
	char *pbuf = malloc(pbuf_sz);
	__u64 grand_count = 0, grand_total = 0;
	double dt;
	int n = 0, keys_done = 0;
	__u32 key = 0, next;

	if (!pbuf || ncpus <= 0 || vsize < sizeof(struct sys_hist)) {
		free(pbuf);
		return;
	}

	/* Iterate keys (bounded: map holds <= SCOPE_MAX_SYSCALL_NR). */
	while (keys_done++ < SCOPE_MAX_SYSCALL_NR &&
	       bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		struct sys_hist cur;
		struct sys_hist *p;

		key = next;
		if (bpf_map_lookup_elem(map_fd, &key, pbuf) != 0)
			continue;
		sum_percpu(pbuf, ncpus, vsize, &cur);

		p = have_prev ? &prev[key] : NULL;
		if (key < SCOPE_MAX_SYSCALL_NR) {
			struct sys_row *r = &rows[n++];
			r->nr = key;
			r->name = syscall_name(key);
			r->d_count = cur.count - (p ? p->count : 0);
			r->d_total_ns = cur.total_ns - (p ? p->total_ns : 0);
			for (int s = 0; s < SCOPE_HIST_SLOTS; s++)
				r->d_slots[s] = cur.slots[s] - (p ? p->slots[s] : 0);
			r->avg_ns = r->d_count ?
				r->d_total_ns / r->d_count : 0;
			r->p50_ns = percentile_ns(r->d_slots, r->d_count, 0.50);
			r->p90_ns = percentile_ns(r->d_slots, r->d_count, 0.90);
			r->p99_ns = percentile_ns(r->d_slots, r->d_count, 0.99);
			grand_count += r->d_count;
			grand_total += r->d_total_ns;
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
	qsort(order, n, sizeof(order[0]), row_cmp);
	if (n > TOP_N)
		n = TOP_N;

	if (json) {
		printf("{\"type\":\"syscalls\",\"interval_ns\":%llu,"
		       "\"count\":%llu,\"top\":[",
		       (unsigned long long)(dt * 1e9),
		       (unsigned long long)grand_count);
		for (int i = 0; i < n; i++) {
			struct sys_row *r = order[i];
			if (i)
				printf(",");
			printf("{\"nr\":%u,\"name\":\"%s\",\"count\":%llu,"
			       "\"avg_ns\":%llu,\"p50_ns\":%llu,"
			       "\"p90_ns\":%llu,\"p99_ns\":%llu}",
			       r->nr, r->name,
			       (unsigned long long)r->d_count,
			       (unsigned long long)r->avg_ns,
			       (unsigned long long)r->p50_ns,
			       (unsigned long long)r->p90_ns,
			       (unsigned long long)r->p99_ns);
		}
		printf("]}\n");
	} else {
		char avg[16], p50[16], p90[16], p99[16];

		printf("== syscalls (%.1fs, %llu events, %llu/s, "
		       "avg %.2fus) ==\n",
		       dt, (unsigned long long)grand_count,
		       (unsigned long long)(grand_count / dt),
		       grand_count ? (double)grand_total / grand_count / 1e3 : 0.0);
		printf("  %-18s %10s %8s %9s %9s %9s %9s\n",
		       "SYSCALL", "COUNT", "RATE/s", "AVG", "P50", "P90",
		       "P99");
		for (int i = 0; i < n; i++) {
			struct sys_row *r = order[i];
			fmt_ns(avg, sizeof(avg), r->avg_ns);
			fmt_ns(p50, sizeof(p50), r->p50_ns);
			fmt_ns(p90, sizeof(p90), r->p90_ns);
			fmt_ns(p99, sizeof(p99), r->p99_ns);
			printf("  %-18s %10llu %8llu %9s %9s %9s %9s\n",
			       r->name, (unsigned long long)r->d_count,
			       (unsigned long long)(r->d_count / dt),
			       avg, p50, p90, p99);
		}
	}
}

/* ---- main ---- */

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

	/* Push config into the kernel before attaching. */
	cfg.sample_rate = opt.sample_rate;
	cfg.target_pid = opt.pid;
	cfg.target_cgroup_id = opt.cgroup_id;
	cfg.min_latency_ns = opt.min_latency_ns;
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
			"scope: tracing exec + syscalls (pid=%u sample=1-in-%u). "
			"Ctrl-C to stop.\n",
			opt.pid, opt.sample_rate);
	}

	/* Short poll timeout (20 ms): responsive shutdown, no busy-loop —
	 * ring_buffer__poll sleeps in epoll until events or timeout. The
	 * syscall histogram dump runs on a 1 s wall-clock tick, driven by
	 * the same loop (no extra thread, no timer signal needed). */
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
