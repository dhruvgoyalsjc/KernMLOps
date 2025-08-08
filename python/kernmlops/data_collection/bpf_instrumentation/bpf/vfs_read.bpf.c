#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct vfs_read_event {
  u32 pid;
  u32 tgid;
  char comm[TASK_COMM_LEN];
  u64 count;
  void* buf;
  s64 ret;
  u8 has_read;      // for verifying o/p of which_read
  u8 has_read_iter; // for verifying o/p of which_read
  u8 which_read;    // 1 = .read, 2 = .read_iter
  u8 success;       // 1 = successful read
  u64 ts_ns;
} vfs_read_event_t;

BPF_PERF_OUTPUT(vfs_read_events);

// Stores start-time + context
BPF_HASH(read_ctx, u64, vfs_read_event_t);

// .read branch detection
int trace_read_branch(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_read_event_t* event = read_ctx.lookup(&id);
  if (event)
    event->which_read = 1;
  return 0;
}

// .read_iter branch detection
int trace_read_iter_branch(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_read_event_t* event = read_ctx.lookup(&id);
  if (event)
    event->which_read = 2;
  return 0;
}

// Entry to vfs_read
int trace_vfs_read_entry(struct pt_regs* ctx, struct file* file, char __user* buf, u64 count,
                         loff_t* pos) {
  u64 id = bpf_get_current_pid_tgid();

  vfs_read_event_t event = {};
  event.pid = (u32)id;
  event.tgid = (u32)(id >> 32);
  event.count = count;
  event.buf = buf;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Timestamp the start of the syscall
  event.ts_ns = bpf_ktime_get_ns();

  event.has_read = 0;
  event.has_read_iter = 0;

  // Check file->f_op->read and file->f_op->read_iter (sanity verification)
  if (file && file->f_op) {
    event.has_read = (file->f_op->read != NULL);
    event.has_read_iter = (file->f_op->read_iter != NULL);
  } else {
    event.has_read = 0;
    event.has_read_iter = 0;
  }

  read_ctx.update(&id, &event);
  return 0;
}

// Track successful read via add_rchar call
// Might just track ret > 0 instead
int trace_add_rchar(struct pt_regs* ctx, struct task_struct* task, ssize_t amt) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_read_event_t* event = read_ctx.lookup(&id);
  if (event)
    event->success = 1;
  return 0;
}

// Return from vfs_read
int trace_vfs_read_return(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_read_event_t* event = read_ctx.lookup(&id);
  if (!event)
    return 0;

  event->ret = PT_REGS_RC(ctx);
  vfs_read_events.perf_submit(ctx, event, sizeof(*event));
  read_ctx.delete(&id);
  return 0;
}
