# Scope — eBPF-based Linux Observability Tool

Low-overhead, production-minded observability for Linux: pure C + libbpf
with CO-RE (Compile Once – Run Everywhere). No bcc, no Python.

> **Status: Phases 1–3 complete** — process exec tracing
> (`sched_process_exec` → ringbuf), syscall latency (raw_syscalls
> enter/exit → log2 histogram → 1 s top-N dump with p50/p90/p99), and
> file I/O (read/write/pread64/pwrite64 at the raw-syscall layer +
> vfs_read/vfs_write refinement, filename + dirname, bytes, latency,
> `-l` threshold). Phases 4–7 (TCP, aggregation, TUI, polish) are
> roadmap items below.

## Prerequisites

Minimum kernel config (check with `zgrep CONFIG_BPF /proc/config.gz`):

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y        # exposes /sys/kernel/btf/vmlinux
```

Ring buffer support needs kernel >= 5.8, and that is the floor: no
perf-buffer fallback for older kernels, by decision. Developed/tested
on 6.x/7.x, x86_64 only.

Packages — Arch/CachyOS:

```sh
sudo pacman -S clang bpftool libbpf libelf gcc make
```

Debian/Ubuntu:

```sh
sudo apt install clang bpftool libbpf-dev libelf-dev gcc make
```

`make deps` checks all of this for you.

## Build

```sh
make deps     # verify clang, bpftool, libbpf headers, kernel BTF
make build    # vmlinux.h + BPF object + skeleton + ./scope binary
make vmlinux  # regenerate src/bpf/vmlinux.h from the running kernel only
make clean
```

What `make build` does, in order:

1. `bpftool btf dump file /sys/kernel/btf/vmlinux format c` → untracked
   `src/bpf/vmlinux.h` (host-specific, never committed).
2. `clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c src/bpf/scope.bpf.c`
   (`__TARGET_ARCH_*` is picked from `uname -m`).
3. `bpftool gen skeleton scope.bpf.o` → `scope.skel.h` (typed
   open/load/attach API — no hand-rolled loading).
4. awk over `/usr/include/asm/unistd_64.h` → `src/syscall_names.h`
   (x86_64 syscall table is stable ABI; generated, never hand-edited).
5. `gcc src/scope.c -lbpf -lelf -lz` → `./scope` (dynamic libbpf link;
   see note below).

## Usage

```text
sudo ./scope [-p PID] [-c CGROUP_PATH] [-s SAMPLE_RATE] [-l MIN_LATENCY_US] [-b MIN_BYTES] [-o json | --no-ui] [-v]
```

Examples:

```sh
sudo ./scope                              # human-readable exec stream
sudo ./scope -o json                      # JSON lines for piping (same as --no-ui)
sudo ./scope -p 1234                      # execs by PID 1234 AND children it spawns
sudo ./scope -c /sys/fs/cgroup/app.slice  # only that cgroup (path -> id via st_ino)
sudo ./scope -s 10                        # sample ~1-in-10 events
sudo ./scope -l 5000                      # only I/O slower than 5 ms
sudo ./scope -b 1048576                   # only I/O of 1 MiB or more
sudo ./scope -v                           # verbose libbpf log (loader/verifier output)
```

Output fields per exec: timestamp, pid, ppid, uid, gid, cgroup id,
comm, filename. Once per second, a top-syscalls table is appended:
interval event count/rate and, per syscall, count, rate, avg and
p50/p90/p99 latency from the in-kernel log2 histogram (JSON mode emits
`{"type":"syscalls", ...}` records instead). File I/O events stream as
`IO READ/WRITE pid=.. tid=.. comm=.. bytes=.. lat file=dir/name`
(`{"type":"io", ...}` in JSON).

`-l N` / `-b N` gate I/O emission: with no thresholds everything
emits; with thresholds, an op emits iff it crosses at least one of
them (slow **or** big). The latency threshold applies to I/O events
only — syscall activity is aggregated into histograms, never emitted
per event, so a latency threshold there would be meaningless by
design.

## Architecture

```text
                  ┌─ tracepoint/sched/sched_process_exec
                  │─ tracepoint/raw_syscalls/sys_enter ─ sampling gate,
  kernel          │   filters, sys_start[ts], io_start[fd] (I/O syscalls)
                  │─ tracepoint/raw_syscalls/sys_exit ─ sys_hist log2
                  │   buckets + I/O emit (reads on 7.x, fallback path)
                  │─ kprobe/kretprobe vfs_read/vfs_write ─ overwrite
                  │   io_start with direct file* (<= 6.x refinement)
                  ▼
  ringbuf  ┌──────────────┐  single 256 KiB BPF_MAP_TYPE_RINGBUF
  (events) │ exec + io    │  (ordering + low userspace overhead)
           └──────────────┘
           ┌──────────────┐  LRU_HASH sys_start[tid] = enter ts (no leak
           │ sys_start    │  on thread death mid-syscall)
           └──────────────┘
           ┌──────────────┐  LRU_HASH io_start[tid] = {ts, fd|file*}
           │ io_start     │  (two-layer dedup: one event per op)
           └──────────────┘
           ┌──────────────┐  PERCPU_HASH sys_hist[nr] = log2 latency slots
           │ sys_hist     │  (in-kernel aggregation, zero per-event traffic)
           └──────────────┘
                  │  ring_buffer__poll, 20 ms timeout (epoll, no busy-loop)
                  │  + 1 s tick: sum percpu hist → top-10 table (p50/90/99)
                  ▼
  userspace  ┌───────────┐
  ./scope    │ scope.c   │── human lines (default) or JSON lines (-o json)
             │ Phase 5→  │── aggregate.c: rolling windows, histograms, tables
             │ Phase 6→  │── ui.c: ncurses multi-panel dashboard
             └───────────┘
  config     ┌───────────┐
  (down)     │ scope_cfg │── ARRAY[1]: sample_rate, target_pid, self_pid,
             │  map      │   target_cgroup_id, min_latency_ns
             └───────────┘
```

Wire format (`src/bpf/scope.bpf.h`, shared BPF↔userspace):

```c
struct scope_event { u32 type; u32 _pad; union { exec_event exec; ... } }
```

`type` is an `enum scope_event_type` (EXEC=1, EXIT/IO/TCP reserved).
New kinds are appended in later phases; old values never change meaning.

## Overhead-reduction design (why, not just what)

- **In-kernel filtering first.** Every program reads the `scope_cfg` map
  before doing any work. A non-matching PID costs a map lookup plus a few
  integer compares — the single most effective overhead control, because
  rejected events never allocate, copy, or cross to userspace.
- **Sampling in-kernel.** `bpf_get_prandom_u32() % sample_rate` drops load
  at the source under heavy event rates instead of flooding the ringbuf.
- **Single ring buffer, drop-on-pressure.** One ordered channel instead of
  per-CPU perf buffers; `ringbuf_reserve` fails gracefully rather than
  stalling the traced task. Lost events are a backpressure signal, not a
  correctness bug, for a sampling observer.
- **Aggregate in-kernel (Phase 2, live).** Pure counters/histograms
  live in `PERCPU` maps (no per-event traffic at all); only events
  needing per-event detail (exec, TCP lifecycle, over-threshold I/O)
  cross the ringbuf. Syscall latency uses in-kernel log2 buckets summed
  on read. Percpu updates are plain increments on the local CPU — no
  atomics, no cross-CPU cacheline traffic; userspace does one bounded
  key iteration per second. (Deviation: the brief said "per-CPU array";
  the map is `PERCPU_HASH` — sparse over 512 possible nrs, bounded at
  512 keys, vs ~140 KB/CPU idle for a flat array. Trade: one hash
  lookup per syscall exit instead of O(1) indexing.)
- **Sampling gate on enter only.** Syscall enter/exit never disagree on
  the sampling decision: the gate lives solely in `sys_enter`, and
  `sys_exit` is driven by the presence of a start entry — no torn
  samples, no start-map leaks from skipped exits.
- **Two-layer I/O with one event per op.** The I/O start slot is written
  at the raw-syscall layer (fd captured from `args[0]`, an ABI stable on
  every kernel) and overwritten by the vfs layer where it exists
  (<= 6.x). Whichever exit fires first consumes the slot; the other
  exits silently. No double counting, no per-op overhead beyond two map
  updates on old kernels and one on new ones.
- **Self-exclusion.** `self_pid` in the config map keeps scope from
  tracing its own event output — without it every emitted event is
  itself a write syscall and the pipeline feeds back on itself (in
  practice: gigabytes of events in seconds).
- **LRU start maps.** A thread dying inside a syscall can't leak
  `sys_start`/`io_start` entries or evict live ones (LRU_HASH, 10k
  entries each).
- **No busy polling.** Userspace sleeps in `ring_buffer__poll` (epoll)
  with a 20 ms timeout — responsive shutdown, ~0 CPU when idle. The 1 s
  histogram dump rides the same loop (no timer thread).

## Verifier notes (issues hit, how resolved)

1. `clang -Werror` vs generated `vmlinux.h`: newer kernels' BTF dump
   emits constructs that trip `-Wmissing-declarations`. The BPF object
   builds with `-Wall -Wno-missing-declarations` (no `-Werror`); the
   userspace binary keeps `-Wall -Wextra` warning-free.
2. **CO-RE matches types by name.** A layout-identical local ctx struct
   named `scope_exec_ctx` failed load with `failed to resolve CO-RE
   relocation ... struct scope_exec_ctx.__data_loc_filename`. Fix: use
   the kernel's own `struct trace_event_raw_sched_process_exec` from
   `vmlinux.h` as the program ctx type. Documented in `scope.bpf.c`.
3. `__data_loc` filename is resolved manually (`(void *)ctx + (off &
   0xffff)`), exact per the trace ABI, instead of assuming pointer
   semantics.
4. **`struct io_event` collides with the kernel's aio `struct io_event`**
   in vmlinux.h (both headers land in the same TU). Renamed to
   `struct scope_io_event`.
5. **Self-tracing feedback loop.** The first I/O build traced its own
   stdout writes: every emitted event triggered another event, filling
   tmpfs with gigabytes in seconds. Fixed with a `self_pid` config field
   checked in the enter gate — and the syscall histogram gate too, so
   scope's own syscalls never pollute its numbers.

## Kernel-7.x findings (why the I/O attach points look like they do)

The spec's attach points were `vfs_read`/`vfs_write` kprobes. Two things
discovered on the 7.2.2 test kernel forced a deviation (verified via
ftrace function_graph, not assumed):

- **7.x reads bypass `vfs_read`.** `__x64_sys_pread64` dispatches
  straight to `f_op->read_iter` (e.g. `shmem_file_read_iter`); `vfs_read`
  is never entered from the read syscalls. `vfs_write` still fires
  (via pwrite64), but relying on vfs probes alone silently loses all
  reads.
- **7.x `__x64_sys_*` takes `struct pt_regs *`.** BTF on 7.2.2 shows
  `FUNC_PROTO '__x64_sys_pread64'` with a single `regs` parameter —
  the expanded-argument signature that kprobes relied on is gone, so
  arg0-based reads of `fd` silently yield the regs pointer.

Resolution: the syscall layer now uses the `raw_syscalls` tracepoints'
`args[0]` (stable tracepoint ABI on every kernel), and the
vfs_read/vfs_write kprobes remain as a refinement layer that overwrites
the per-thread slot where they still fire. The dedup scheme guarantees
exactly one event per I/O op on any kernel.

Consequences, stated as deviations:

- **`bpf_core_field_exists()` is unused.** The brief asked to guard
  optional fields with it where kernel versions differ. The 7.x
  differences found were structural (function signatures, dispatch
  paths), not optional struct fields, so they were handled
  architecturally instead. No optional field access exists in the code.
- **Latency scoping differs per kernel.** On <= 6.x, I/O latency is
  vfs-scoped (vfs entry -> exit); on 7.x, reads are syscall-scoped
  (sys_enter -> sys_exit) because vfs_read never fires. `-l` compares
  the same order of magnitude on both, but they are not identical
  quantities.
- **Failed/EOF I/O is dropped** (ret <= 0 emits nothing) — "bytes
  moved" only makes sense for completed reads/writes.
- **`min_latency_ns` gates I/O events only**; syscall latency is
  histogrammed in-kernel and never emitted per event (see Usage).

## Known limitations (Phases 1–3)

- Exec + syscalls + file I/O only: no exit events, argv (filename
  only), no TCP yet.
- `-p` matches the exec'ing task **or its parent** (fork+exec children
  have their own pid); syscall/I/O programs match tid **or** tgid (all
  threads of the process).
- Filenames are dentry name + one-hop parent dir only; no full path in
  the kernel (full-path work is userspace, planned with aggregation).
- Reads/writes are traced at syscall level (fd resolution via
  current->files); an fd closed by another thread mid-op yields an
  empty name (graceful, bounded).
- Syscall percentiles are bucket upper bounds from the log2 histogram
  (slot s = [2^(s-1), 2^s) ns; slot 31 saturates), not exact values.
- Syscall histogram is cumulative since start; interval deltas are
  computed in userspace by diffing snapshots. The dump sorts by count
  (latency columns ride along); a latency-sorted view arrives with the
  TUI.
- Dynamic libbpf link (`-lbpf`) for now. Static linking is the goal
  (Phase 7): it needs libbpf and zlib built from source, since only
  `libelf.a` ships on this host (`libbpf.a`/`libz.a` absent).
  Documented alternative until then: `pacman -S libbpf` / `apt install libbpf1`.
- x86_64 only, by decision — single-arch keeps BPF CFLAGS, the syscall
  table, and struct assumptions simple.

## Roadmap

- **Phase 4** — TCP: connect/close/accept hooks, 5-tuple via CO-RE,
  connection table with lifecycle.
- **Phase 5** — aggregation layer + filtering across all sources.
- **Phase 6** — ncurses multi-panel TUI (renderer decided: ncurses).
- **Phase 7** — CLI polish, JSON mode parity, README final pass.

## License

GPL-2.0 (BPF programs must be GPL-compatible with the kernel).
