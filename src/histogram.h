/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SCOPE_HISTOGRAM_H
#define SCOPE_HISTOGRAM_H

#include <linux/types.h>
#include <stddef.h>

#include "bpf/scope.bpf.h"

#define HIST_TOP_N 10

/* One aggregated syscall row. delta holds the interval diff of the
 * in-kernel histogram. Percentiles derive from it. */
struct sys_row {
	__u32 nr;
	const char *name;
	struct sys_hist delta;
	__u64 avg_ns, p50_ns, p90_ns, p99_ns;
};

const char *hist_syscall_name(__u32 nr);
__u64 hist_slot_upper(int slot);
__u64 hist_percentile(const __u64 *slots, __u64 count, double p);
size_t hist_percpu_stride(size_t vsize);
void hist_sum_percpu(const void *vals, int ncpus, size_t vsize,
		     struct sys_hist *out);
void hist_diff_row(__u32 nr, const struct sys_hist *cur,
		   const struct sys_hist *prev, int have_prev,
		   struct sys_row *out);
int hist_row_cmp(const void *a, const void *b);

#endif
