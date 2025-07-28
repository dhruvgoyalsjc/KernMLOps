#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Change this if you want to filter by a specific PID
const volatile pid_t target_pid = 0;

// Used to identify syscalls by ID
struct syscall_event_t {
  1 u64 timestamp_ns;
  u32 pid;
  u32 syscall_id;
  u64 latency_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);   // pid + tid
  __type(value, u64); // timestamp
  __uint(max_entries, 4096);
} enter_timestamps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  if (target_pid != 0 && pid >> 32 != target_pid)
    return 0;

  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&enter_timestamps, &pid, &ts, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  if (target_pid != 0 && pid >> 32 != target_pid)
    return 0;

  u64* start_ts = bpf_map_lookup_elem(&enter_timestamps, &pid);
  if (!start_ts)
    return 0;

  u64 end_ts = bpf_ktime_get_ns();
  u64 delta = end_ts - *start_ts;
  bpf_map_delete_elem(&enter_timestamps, &pid);

  struct syscall_event_t event = {};
  event.timestamp_ns = end_ts;
  event.latency_ns = delta;
  event.pid = pid >> 32; // get only PID (not thread id)
  event.syscall_id = ctx->id;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}
