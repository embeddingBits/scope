/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "output.h"

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

static void fmt_ts(char *out, size_t n, __u64 ts_ns)
{
	time_t sec = (time_t)(ts_ns / 1000000000ULL);
	struct tm tm;

	localtime_r(&sec, &tm);
	strftime(out, n, "%H:%M:%S", &tm);
	size_t len = strlen(out);

	snprintf(out + len, n - len, ".%03llu",
		 (ts_ns / 1000000ULL) % 1000ULL);
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

static const char *io_kind_str(__u32 kind, bool json)
{
	if (kind == SCOPE_IO_READ)
		return json ? "read" : "READ";
	return json ? "write" : "WRITE";
}

static void print_exec_human(const struct exec_event *e)
{
	char ts[32];

	fmt_ts(ts, sizeof(ts), e->timestamp_ns);
	printf("%s EXEC pid=%-7u ppid=%-7u uid=%-5u comm=%.16s file=%.256s cgroup=%llu\n",
	       ts, e->pid, e->ppid, e->uid, e->comm, e->filename,
	       (unsigned long long)e->cgroup_id);
}

static void print_exec_json(const struct exec_event *e)
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

static void print_io_human(const struct scope_io_event *e)
{
	char ts[32], lat[32];

	fmt_ts(ts, sizeof(ts), e->timestamp_ns);
	fmt_ns(lat, sizeof(lat), e->delta_ns);
	printf("%s IO  %-5s pid=%-7u tid=%-7u comm=%.16s bytes=%-11lld %s file=%s/%s\n",
	       ts, io_kind_str(e->kind, false), e->pid, e->tid, e->comm,
	       (long long)e->bytes, lat, e->dirname, e->filename);
}

static void print_io_json(const struct scope_io_event *e)
{
	printf("{\"type\":\"io\",\"ts\":%llu,\"pid\":%u,\"tid\":%u,"
	       "\"op\":\"%s\",\"fd\":%u,\"bytes\":%lld,\"latency_ns\":%llu,"
	       "\"comm\":",
	       (unsigned long long)e->timestamp_ns, e->pid, e->tid,
	       io_kind_str(e->kind, true), e->fd, (long long)e->bytes,
	       (unsigned long long)e->delta_ns);
	json_escape(stdout, e->comm, sizeof(e->comm));
	printf(",\"file\":");
	json_escape(stdout, e->filename, sizeof(e->filename));
	printf(",\"dir\":");
	json_escape(stdout, e->dirname, sizeof(e->dirname));
	printf("}\n");
}

int output_event(const struct scope_event *ev, bool json)
{
	switch (ev->type) {
	case SCOPE_EVENT_EXEC:
		if (json)
			print_exec_json(&ev->data.exec);
		else
			print_exec_human(&ev->data.exec);
		return 0;
	case SCOPE_EVENT_IO:
		if (json)
			print_io_json(&ev->data.io);
		else
			print_io_human(&ev->data.io);
		return 0;
	default:
		return -1;
	}
}

void output_syscalls(struct sys_row *const *top, int n, double dt_sec,
		     unsigned long long grand_count,
		     unsigned long long grand_total, bool json)
{
	if (json) {
		printf("{\"type\":\"syscalls\",\"interval_ns\":%llu,"
		       "\"count\":%llu,\"top\":[",
		       (unsigned long long)(dt_sec * 1e9),
		       grand_count);
		for (int i = 0; i < n; i++) {
			struct sys_row *r = top[i];

			if (i)
				printf(",");
			printf("{\"nr\":%u,\"name\":\"%s\",\"count\":%llu,"
			       "\"avg_ns\":%llu,\"p50_ns\":%llu,"
			       "\"p90_ns\":%llu,\"p99_ns\":%llu}",
			       r->nr, r->name,
			       (unsigned long long)r->delta.count,
			       (unsigned long long)r->avg_ns,
			       (unsigned long long)r->p50_ns,
			       (unsigned long long)r->p90_ns,
			       (unsigned long long)r->p99_ns);
		}
		printf("]}\n");
		return;
	}

	char avg[16], p50[16], p90[16], p99[16];

	printf("== syscalls (%.1fs, %llu events, %llu/s, "
	       "avg %.2fus) ==\n",
	       dt_sec, grand_count,
	       (unsigned long long)(grand_count / dt_sec),
	       grand_count ? (double)grand_total / grand_count / 1e3 : 0.0);
	printf("  %-18s %10s %8s %9s %9s %9s %9s\n",
	       "SYSCALL", "COUNT", "RATE/s", "AVG", "P50", "P90",
	       "P99");
	for (int i = 0; i < n; i++) {
		struct sys_row *r = top[i];

		fmt_ns(avg, sizeof(avg), r->avg_ns);
		fmt_ns(p50, sizeof(p50), r->p50_ns);
		fmt_ns(p90, sizeof(p90), r->p90_ns);
		fmt_ns(p99, sizeof(p99), r->p99_ns);
		printf("  %-18s %10llu %8llu %9s %9s %9s %9s\n",
		       r->name, (unsigned long long)r->delta.count,
		       (unsigned long long)(r->delta.count / dt_sec),
		       avg, p50, p90, p99);
	}
}
