#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct vfs_write_event {
  u32 pid;
  u32 tgid;
  char comm[TASK_COMM_LEN];
  u64 count;
  void* buf;
  s64 ret;
  u8 has_write;      // for verifying o/p of which_write
  u8 has_write_iter; // for verifying o/p of which_write
  u8 which_write;    // 1 = .write, 2 = .write_iter
  u8 success;        // 1 = successful write (ret > 0)
  u64 ts_ns;
} vfs_write_event_t;

BPF_PERF_OUTPUT(vfs_write_events);

// Stores start-time + context
BPF_HASH(write_ctx, u64, vfs_write_event_t);

// .write branch detection
int trace_write_branch(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_write_event_t* event = write_ctx.lookup(&id);
  if (event)
    event->which_write = 1;
  return 0;
}

// .write_iter branch detection
int trace_write_iter_branch(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_write_event_t* event = write_ctx.lookup(&id);
  if (event)
    event->which_write = 2;
  return 0;
}

// Entry to vfs_write
int trace_vfs_write_entry(struct pt_regs* ctx, struct file* file, char __user* buf, u64 count,
                          loff_t* pos) {
  u64 id = bpf_get_current_pid_tgid();

  vfs_write_event_t event = {};
  event.pid = (u32)id;
  event.tgid = (u32)(id >> 32);
  event.count = count;
  event.buf = buf;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Timestamp the start of the syscall
  event.ts_ns = bpf_ktime_get_ns();

  // Check file->f_op->write and file->f_op->write_iter (sanity verification)
  if (file && file->f_op) {
    event.has_write = (file->f_op->write != NULL);
    event.has_write_iter = (file->f_op->write_iter != NULL);
  } else {
    event.has_write = 0;
    event.has_write_iter = 0;
  }

  write_ctx.update(&id, &event);
  return 0;
}

// Track successful write via add_wchar call
int trace_add_wchar(struct pt_regs* ctx, struct task_struct* task, ssize_t amt) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_write_event_t* event = write_ctx.lookup(&id);
  if (event)
    event->success = 1;
  return 0;
}

// Return from vfs_write
int trace_vfs_write_return(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  vfs_write_event_t* event = write_ctx.lookup(&id);
  if (!event)
    return 0;

  event->ret = PT_REGS_RC(ctx);
  vfs_write_events.perf_submit(ctx, event, sizeof(*event));
  write_ctx.delete(&id);
  return 0;
}
