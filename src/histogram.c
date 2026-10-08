/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <string.h>

#include "histogram.h"
#include "syscall_names.h"

#define HIST_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

const char *hist_syscall_name(__u32 nr)
{
	if (nr < HIST_ARRAY_SIZE(syscall_names) && syscall_names[nr])
		return syscall_names[nr];
	static char buf[4][16];
	static unsigned idx;
	char *b = buf[idx++ % 4];

	snprintf(b, sizeof(buf[0]), "sys_%u", nr);
	return b;
}

__u64 hist_slot_upper(int slot)
{
	if (slot <= 0)
		return 0;
	return 1ULL << slot;
}

__u64 hist_percentile(const __u64 *slots, __u64 count, double p)
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
			return hist_slot_upper(s);
	}
	return hist_slot_upper(SCOPE_HIST_SLOTS - 1);
}

size_t hist_percpu_stride(size_t vsize)
{
	return (vsize + 7) & ~7UL;
}

void hist_sum_percpu(const void *vals, int ncpus, size_t vsize,
		     struct sys_hist *out)
{
	size_t stride = hist_percpu_stride(vsize);

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

void hist_diff_row(__u32 nr, const struct sys_hist *cur,
		   const struct sys_hist *prev, int have_prev,
		   struct sys_row *out)
{
	out->nr = nr;
	out->name = hist_syscall_name(nr);
	out->delta.count = cur->count - (have_prev ? prev->count : 0);
	out->delta.total_ns = cur->total_ns -
		(have_prev ? prev->total_ns : 0);
	for (int s = 0; s < SCOPE_HIST_SLOTS; s++)
		out->delta.slots[s] = cur->slots[s] -
			(have_prev ? prev->slots[s] : 0);
	out->avg_ns = out->delta.count ?
		out->delta.total_ns / out->delta.count : 0;
	out->p50_ns = hist_percentile(out->delta.slots, out->delta.count,
				     0.50);
	out->p90_ns = hist_percentile(out->delta.slots, out->delta.count,
				     0.90);
	out->p99_ns = hist_percentile(out->delta.slots, out->delta.count,
				     0.99);
}

int hist_row_cmp(const void *a, const void *b)
{
	const struct sys_row *ra = *(struct sys_row *const *)a;
	const struct sys_row *rb = *(struct sys_row *const *)b;

	if (ra->delta.count < rb->delta.count)
		return 1;
	if (ra->delta.count > rb->delta.count)
		return -1;
	return 0;
}
