import signal
import subprocess
import time
from dataclasses import dataclass
from typing import cast

from data_schema import GraphEngine
from kernmlops_benchmark.benchmark import Benchmark, GenericBenchmarkConfig
from kernmlops_benchmark.errors import (
    BenchmarkNotInCollectionData,
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_config import ConfigBase
from pytimeparse.timeparse import timeparse


@dataclass(frozen=True)
class FioConfig(ConfigBase):
    ioengine: str = "sync" # supposedly this is better for benchmarking vfs read and write
    blocksize: str = "4k"
    size: str = "1G"
    numjobs: int = 1
    filename: str = "fio-testfile"
    runtime: int = 60       # in seconds
    direct: bool = True
    sleep: str | None = None

class FioBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "fio"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return FioConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        spec    = cast(FioConfig, getattr(config, cls.name()))
        return FioBenchmark(generic_config=generic, config=spec)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: FioConfig):
        self.generic_config = generic_config
        self.config         = config
        self.benchmark_dir  = self.generic_config.get_benchmark_dir() / "fio"
        self.process: subprocess.Popen | None = None

    def is_configured(self) -> bool:
        return (self.benchmark_dir / "bin" / "fio").exists()

    def setup(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        self.generic_config.generic_setup()

    def run(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        bin_path = self.benchmark_dir / "bin" / "fio"
        cmd = [
            str(bin_path),
            f"--ioengine={self.config.ioengine}",
            f"--bs={self.config.blocksize}",
            f"--size={self.config.size}",
            f"--numjobs={self.config.numjobs}",
            f"--filename={self.config.filename}",
            f"--runtime={self.config.runtime}",
            f"--direct={int(self.config.direct)}",
            "--name=benchmark"
        ]
        if self.config.sleep:
            time.sleep(timeparse(self.config.sleep))
        self.process = subprocess.Popen(cmd)

    def poll(self) -> int | None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        return self.process.poll()

    def wait(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.wait()

    def kill(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.send_signal(signal.SIGINT)
        self.process.wait()

    @classmethod
    def plot_events(cls, graph_engine: GraphEngine) -> None:
        if graph_engine.collection_data.benchmark != cls.name():
            raise BenchmarkNotInCollectionData()
        # no custom events
        pass
