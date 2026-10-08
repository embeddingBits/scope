/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SCOPE_OUTPUT_H
#define SCOPE_OUTPUT_H

#include <stdbool.h>

#include "histogram.h"

int output_event(const struct scope_event *ev, bool json);
void output_syscalls(struct sys_row *const *top, int n, double dt_sec,
		     unsigned long long grand_count,
		     unsigned long long grand_total, bool json);

#endif
