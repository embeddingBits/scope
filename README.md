# Scope: eBPF-based Linux observability tool

Scope watches a Linux box through eBPF and prints what it sees. It
traces process execs with pid, ppid, uid, and filename; per-syscall
latency as a top-10 table with p50/p90/p99, refreshed every second;
and file read and write events with the file name, byte count, and
latency. Output is human-readable lines by default, or JSON lines
with `-o json` for piping. Needs x86_64, kernel 5.8 or newer with
BTF, and root to run.

## TODO

Code health, from the architecture review:

- Fix the output mode at construction. `output_event` still takes a
  json flag on every call. Set the mode once at startup so the four
  printers sit behind one submit interface.
- Pull the `-l`/`-b` emit rule out of `io_emit` into a small policy
  check (delta and bytes in, emit decision out). Slot consume, file
  resolve, and submit stay in emit.
- Stop committing the generated table. Ignore `src/syscall_names.h`
  the way `vmlinux.h` and the skeleton are ignored, and let the
  Makefile rule regen it at build time.

Features:

- TCP tracing: connect/close/accept hooks, 5-tuple via CO-RE,
  connection table with lifecycle.
- Aggregation layer with filtering across all sources, plus full-path
  resolution in userspace.
- ncurses multi-panel TUI with a latency-sorted syscall view.
- CLI polish, JSON mode parity, static libbpf link.

