#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct data_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 count;
  void* buf;
  int which_read; // 1 = .read, 2 = .read_iter
  s64 ret;
  int success; // 1 = successful read, 0 = not
};

BPF_PERF_OUTPUT(events);
BPF_HASH(call_type, u32, u32);           // For tracking .read vs .read_iter
BPF_HASH(in_vfs_read, u32, u8);          // For tracking if we're inside vfs_read
BPF_HASH(temp_data, u32, struct data_t); // To stash count and buf
BPF_HASH(successful_read, u32, u64);     // To track if read was success

// Entry to vfs_read
int trace_entry(struct pt_regs* ctx, struct file* file, char __user* buf, u64 count, loff_t* pos) {
  u32 pid = bpf_get_current_pid_tgid();

  struct data_t data = {};
  data.pid = pid;
  data.count = count;
  data.buf = buf;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  temp_data.update(&pid, &data);

  call_type.update(&pid, &(u32){0});
  in_vfs_read.update(&pid, &(u8){1});
  return 0;
}

// .read branch
int trace_read_branch(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  if (!in_vfs_read.lookup(&pid))
    return 0;

  call_type.update(&pid, &(u32){1});
  return 0;
}

// .read_iter branch
int trace_read_iter_branch(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  if (!in_vfs_read.lookup(&pid))
    return 0;

  call_type.update(&pid, &(u32){2});
  return 0;
}

int trace_add_rchar(struct pt_regs* ctx, struct task_struct* tsk, ssize_t amt) {
  u32 pid = bpf_get_current_pid_tgid();
  successful_read.update(&pid, &(u64){1});
  return 0;
}

// Return from vfs_read
int trace_return(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();

  struct data_t* stash = temp_data.lookup(&pid);
  if (!stash)
    return 0;

  struct data_t out = *stash;
  out.ret = PT_REGS_RC(ctx);

  u32* which = call_type.lookup(&pid);
  if (which)
    out.which_read = *which;

  u64* success = successful_read.lookup(&pid);
  if (success) {
    out.success = 1;
    successful_read.delete(&pid);
  }

  events.perf_submit(ctx, &out, sizeof(out));

  temp_data.delete(&pid);
  call_type.delete(&pid);
  in_vfs_read.delete(&pid);
  return 0;
}
