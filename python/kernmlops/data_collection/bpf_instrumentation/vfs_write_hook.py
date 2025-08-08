from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable
from data_schema.vfs_write import (
    VFSWriteDataTable,  # You must define this schema separately
)


@dataclass(frozen=True)
class VFSWriteEvent:
    pid: int
    tgid: int
    comm: str
    count: int
    buf: int
    ret: int
    has_write: int
    has_write_iter: int
    which_write: int
    success: int
    ts_ns: int

class VFSWriteBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "vfs_write"

    def __init__(self):
        self.bpf_text = open(Path(__file__).parent / "bpf/vfs_write.bpf.c", "r").read()
        self.trace_process: list[VFSWriteEvent] = []

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach entry + return to vfs_write
        self.bpf.attach_kprobe(event=b"vfs_write", fn_name=b"trace_vfs_write_entry")
        self.bpf.attach_kretprobe(event=b"vfs_write", fn_name=b"trace_vfs_write_return")

        # NEED TO STILL FIND OFFSETS
        self.bpf.attach_kprobe(event=b"vfs_write+0xfd", fn_name=b"trace_write_branch")
        self.bpf.attach_kprobe(event=b"vfs_write+0x24f", fn_name=b"trace_write_iter_branch")
        self.bpf.attach_kprobe(event=b"vfs_write+0x392", fn_name=b"trace_write_iter_branch")
        self.bpf.attach_kprobe(event=b"vfs_write+0x2e7", fn_name=b"trace_add_wchar")

        self.bpf["vfs_write_events"].open_perf_buffer(self.vfs_write_eh, page_cnt=128)

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def data(self) -> list[CollectionTable]:
        return [
            VFSWriteDataTable.from_df_id(
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

    def vfs_write_eh(self, cpu, data, size):
        event = self.bpf["vfs_write_events"].event(data)
        self.trace_process.append(
            VFSWriteEvent(
                pid=event.pid,
                tgid=event.tgid,
                comm=event.comm.decode("utf-8", "replace").rstrip("\x00"),
                count=event.count,
                buf=int(event.buf),
                ret=event.ret,
                has_write=event.has_write,
                has_write_iter=event.has_write_iter,
                which_write=event.which_write,
                success=event.success,
                ts_ns=event.ts_ns,
            )
        )
