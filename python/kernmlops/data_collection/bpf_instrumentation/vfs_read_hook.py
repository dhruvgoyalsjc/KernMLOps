from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable
from data_schema.vfs_read import (
    VFSReadDataTable,  # We defined this schema separately
)


@dataclass(frozen=True)
class VFSReadEvent:
    pid: int
    tgid: int
    comm: str
    count: int
    buf: int
    ret: int
    has_read: int
    has_read_iter: int
    which_read: int
    success: int
    ts_ns: int

class VFSReadBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "vfs_read"

    def __init__(self):
        self.bpf_text = open(Path(__file__).parent / "bpf/vfs_read.bpf.c", "r").read()
        self.trace_process: list[VFSReadEvent] = []

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Match updated function names from vfs_read.bpf.c
        self.bpf.attach_kprobe(event=b"vfs_read", fn_name=b"trace_vfs_read_entry")
        self.bpf.attach_kretprobe(event=b"vfs_read", fn_name=b"trace_vfs_read_return")

        self.bpf.attach_kprobe(event=b"vfs_read+0xaf", fn_name=b"trace_read_branch")
        self.bpf.attach_kprobe(event=b"vfs_read+0x208", fn_name=b"trace_read_iter_branch")
        self.bpf.attach_kprobe(event=b"vfs_read+0x310", fn_name=b"trace_read_iter_branch")
        self.bpf.attach_kprobe(event=b"vfs_read+0x11d", fn_name=b"trace_add_rchar")


        self.bpf["vfs_read_events"].open_perf_buffer(self.vfs_read_eh, page_cnt=128)

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def data(self) -> list[CollectionTable]:
        return [
            VFSReadDataTable.from_df_id(
                pl.DataFrame(self.trace_process),
                collection_id=self.collection_id,
            )
        ]

    def clear(self):
        self.trace_process.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables

    def vfs_read_eh(self, cpu, data, size):
        event = self.bpf["vfs_read_events"].event(data)
        self.trace_process.append(
            VFSReadEvent(
                pid=event.pid,
                tgid=event.tgid,
                comm=event.comm.decode("utf-8", "replace").rstrip("\x00"),
                count=event.count,
                buf=int(event.buf),
                ret=event.ret,
                has_read=event.has_read,
                has_read_iter=event.has_read_iter,
                which_read=event.which_read,
                success=event.success,
                ts_ns=event.ts_ns,
            )
        )
