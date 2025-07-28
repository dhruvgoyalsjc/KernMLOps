import ctypes
from typing import Optional

from data_collection.bpf_instrumentation.bpf_hook import BPFProgram


class SyscallEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("syscall_id", ctypes.c_uint),
        ("latency_ns", ctypes.c_ulonglong),
    ]


class SyscallLatencyHook(BPFProgram):
    BPF_SRC = "bpf/syscall_latency.c"
    BPF_FUNCTIONS = ["trace_sys_enter", "trace_sys_exit"]
    STRUCT = SyscallEvent
    PERF_MAP = "events"

    def __init__(self, target_pid: Optional[int] = None):
        self.target_pid = target_pid
        super().__init__()

    @classmethod
    def name(cls) -> str:
        return "syscall_latency"

    def get_config(self):
        return {"target_pid": self.target_pid or 0}

    def extract_event(self, event: SyscallEvent) -> dict:
        return {
            "timestamp_ns": event.timestamp_ns,
            "pid": event.pid,
            "syscall_id": event.syscall_id,
            "latency_ns": event.latency_ns,
        }
