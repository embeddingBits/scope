# Scope — eBPF-based Linux Observability Tool

Low-overhead, production-minded observability for Linux: pure C + libbpf
with CO-RE (Compile Once – Run Everywhere). No bcc, no Python.

> **Status: Phase 1 complete** — process exec tracing
> (`sched_process_exec` → ringbuf → human/JSON output). Phases 2–7
> (syscalls, file I/O, TCP, aggregation, TUI, polish) are roadmap items
> below; the event ABI and config map are already shaped for them.

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
4. `gcc src/scope.c -lbpf -lelf -lz` → `./scope` (dynamic libbpf link;
   see note below).

## Usage

```text
sudo ./scope [-p PID] [-c CGROUP_PATH] [-s SAMPLE_RATE] [-l MIN_LATENCY_US] [-o json | --no-ui] [-v]
```

Examples:

```sh
sudo ./scope                              # human-readable exec stream
sudo ./scope -o json                      # JSON lines for piping (same as --no-ui)
sudo ./scope -p 1234                      # execs by PID 1234 AND children it spawns
sudo ./scope -c /sys/fs/cgroup/app.slice  # only that cgroup (path -> id via st_ino)
sudo ./scope -s 10                        # sample ~1-in-10 events
sudo ./scope -v                           # verbose libbpf log (loader/verifier output)
```

Output fields per exec: timestamp, pid, ppid, uid, gid, cgroup id,
comm, filename. `-l` is parsed and stored in the kernel config map now;
it takes effect in the I/O + syscall phases.

## Architecture

```text
                  ┌─ tracepoint/sched/sched_process_exec
  kernel          │   1. config-map check (pid/cgroup/sample) → early return
                  │   2. ringbuf_reserve (drop on pressure, never block)
                  │   3. fill exec_event, ringbuf_submit
                  ▼
  ringbuf  ┌──────────────┐  single 256 KiB BPF_MAP_TYPE_RINGBUF
  (events) │ sched exec   │  (ordering + low userspace overhead)
           └──────────────┘
                  │  ring_buffer__poll, 20 ms timeout (epoll, no busy-loop)
                  ▼
  userspace  ┌───────────┐
  ./scope    │ scope.c   │── human lines (default) or JSON lines (-o json)
             │ Phase 5→  │── aggregate.c: rolling windows, histograms, tables
             │ Phase 6→  │── ui.c: ncurses multi-panel dashboard
             └───────────┘
  config     ┌───────────┐
  (down)     │ scope_cfg │── ARRAY[1]: sample_rate, target_pid,
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
- **Aggregate in-kernel (Phases 2+).** Pure counters/histograms live in
  `PERCPU` maps (no per-event traffic at all); only events needing
  per-event detail (exec, TCP lifecycle, over-threshold I/O) cross the
  ringbuf. Syscall latency uses in-kernel log2 buckets summed on read.
- **No busy polling.** Userspace sleeps in `ring_buffer__poll` (epoll)
  with a 20 ms timeout — responsive shutdown, ~0 CPU when idle.

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

## Known limitations (Phase 1)

- Exec only: no exit events, argv (filename only), syscall/I/O/TCP yet.
- `-p` matches the exec'ing task **or its parent**, so `scope -p SHELL`
  shows what that shell launches (fork+exec children have their own
  pid). Later-phase programs filter on current pid only.
- Dynamic libbpf link (`-lbpf`) for now. Static linking is the goal
  (Phase 7): it needs libbpf and zlib built from source, since only
  `libelf.a` ships on this host (`libbpf.a`/`libz.a` absent).
  Documented alternative until then: `pacman -S libbpf` / `apt install libbpf1`.
- x86_64 only, by decision — single-arch keeps BPF CFLAGS, the syscall
  table, and struct assumptions simple.

## Roadmap

- **Phase 2** — syscall latency: raw_syscalls enter/exit, per-thread
  start-time hash, in-kernel log2 histogram, top-syscalls dump.
- **Phase 3** — file I/O: vfs_read/vfs_write kprobes, filename via
  dentry, size/latency events with sampling + threshold.
- **Phase 4** — TCP: connect/close/accept hooks, 5-tuple via CO-RE,
  connection table with lifecycle.
- **Phase 5** — aggregation layer + filtering across all sources.
- **Phase 6** — ncurses multi-panel TUI (renderer decided: ncurses).
- **Phase 7** — CLI polish, JSON mode parity, README final pass.

## License

GPL-2.0 (BPF programs must be GPL-compatible with the kernel).
