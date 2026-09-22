/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scope.c — Scope userspace: load/attach BPF, poll ringbuf, print events.
 *
 * Phase 1: exec events only, human-readable lines or JSON lines
 * (--no-ui / -o json). Aggregation + TUI arrive in later phases.
 */
#include <argp.h>
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

/* ---- main ---- */

int main(int argc, char **argv)
{
	struct scope_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct scope_config cfg = {};
	const __u32 zero = 0;
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
			"scope: tracing exec (pid=%u sample=1-in-%u). "
			"Ctrl-C to stop.\n",
			opt.pid, opt.sample_rate);
	}

	/* Short poll timeout (20 ms): responsive shutdown, no busy-loop —
	 * ring_buffer__poll sleeps in epoll until events or timeout. */
	while (!stop) {
		err = ring_buffer__poll(rb, 20);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n",
				strerror(-err));
			err = 1;
			goto out;
		}
	}
	err = 0;
out:
	ring_buffer__free(rb);
	scope_bpf__destroy(skel);
	return err;
}
