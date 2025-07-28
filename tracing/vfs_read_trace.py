import os

from bcc import BPF

tracer_pid = os.getpid()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 count;
    void *buf;
    int which_read; // 1 = .read, 2 = .read_iter
    s64 ret;
};
BPF_PERF_OUTPUT(events);
BPF_HASH(call_type, u32, u32);
BPF_HASH(in_vfs_read, u32, u8);

int trace_entry(struct pt_regs *ctx, struct file *file, char __user *buf, u64 count, loff_t *pos) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    data.count = count;
    data.buf = buf;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    call_type.update(&pid, &(u32){0});
    events.perf_submit(ctx, &data, sizeof(data));

    u8 flag = 1;
    in_vfs_read.update(&pid, &flag);

    return 0;
}

int trace_read_branch(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    u8 *in_read = in_vfs_read.lookup(&pid);
    if (!in_read) return 0;

    u32 mode = 1;
    call_type.update(&pid, &mode);
    return 0;
}

int trace_read_iter_branch(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    u8 *in_read = in_vfs_read.lookup(&pid);
    if (!in_read) return 0;

    u32 mode = 2;
    call_type.update(&pid, &mode);
    return 0;
}

int trace_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ret = PT_REGS_RC(ctx);

    u32 *which = call_type.lookup(&pid);
    if (which) data.which_read = *which;
    events.perf_submit(ctx, &data, sizeof(data));

    in_vfs_read.delete(&pid);

    return 0;
}

int trace_add_rchar(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    u8 *in_read = in_vfs_read.lookup(&pid);
    if (!in_read) return 0;

    //bpf_trace_printk("This means the read was successful: add_rchar called by pid %d\\n", pid);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Attach probes
b.attach_kprobe(event="vfs_read", fn_name="trace_entry")               # Entry to vfs_read
b.attach_kretprobe(event="vfs_read", fn_name="trace_return")          # Return from vfs_read
b.attach_kprobe(event="vfs_read+0xaf", fn_name="trace_read_branch")      # Offset for .read dispatch
b.attach_kprobe(event="vfs_read+0x208", fn_name="trace_read_iter_branch")  # Offset for .read_iter dispatch
b.attach_kprobe(event="vfs_read+0x11d", fn_name="trace_add_rchar")    # Offset for fsnotify_access

# Print handler
def print_event(cpu, data, size):
    event = b["events"].event(data)

    comm_str = event.comm.decode()
    if comm_str not in ("read_test", "read_iter_test"):
        return  # Skip logging if this event was triggered by the tracer itself
    print(f"PID {event.pid} ({event.comm.decode()}): count={event.count}, buf={event.buf}, "
          f"return={event.ret}, which_read={event.which_read}")

# Open perf buffer
b["events"].open_perf_buffer(print_event)
print("Tracing vfs_read... Ctrl-C to end.")

# Main loop
try:
    while True:
        b.perf_buffer_poll(timeout=100)
        # time.sleep(0.01)
except KeyboardInterrupt:
    print("Detaching probes cleanly...")
    b.cleanup()
