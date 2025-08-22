import signal
import subprocess
import time
from dataclasses import dataclass
from typing import cast

from data_schema import GraphEngine, demote
from kernmlops_benchmark.benchmark import Benchmark, GenericBenchmarkConfig
from kernmlops_benchmark.errors import (
    BenchmarkError,
    BenchmarkNotInCollectionData,
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_config import ConfigBase
from pytimeparse.timeparse import timeparse


@dataclass(frozen=True)
class PostgresqlConfig(ConfigBase):
    repeat: int = 1
    outer_repeat: int = 1
    # Core operation parameters
    field_count: int = 10
    field_length: int = 100
    min_field_length: int = 1
    operation_count: int = 1000
    record_count: int = 1000
    read_proportion: float = 0.5
    update_proportion: float = 0.5
    scan_proportion: float = 0.0
    insert_proportion: float = 0.0
    rmw_proportion: float = 0.00
    delete_proportion: float = 0.00

    # Distribution and performance parameters
    field_length_distribution: str = "uniform"
    request_distribution: str = "uniform"
    thread_count: int = 1
    target: int = 1000
    sleep: str | None = None
    server_sleep: str | None = None
    explicit_purge: bool = False


size_postgresql = [
    "psql",
    "-U", "ycsbuser",
    "-h", "localhost",
    "-p", "5433",
    "-d", "ycsb",
    "-c", "SELECT COUNT(*) FROM usertable;",
]


class PostgresqlBenchmark(Benchmark):

    @classmethod
    def name(cls) -> str:
        return "postgresql"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return PostgresqlConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic_config = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        postgresql_config = cast(PostgresqlConfig, getattr(config, cls.name()))
        return PostgresqlBenchmark(generic_config=generic_config, config=postgresql_config)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: PostgresqlConfig):
        self.generic_config = generic_config
        self.config = config
        self.benchmark_dir = self.generic_config.get_benchmark_dir() / "ycsb"
        self.postgresql_dir = self.generic_config.get_benchmark_dir() / "postgresql"
        self.process: subprocess.Popen | None = None
        self.server: subprocess.Popen | None = None

    def is_configured(self) -> bool:
        return self.benchmark_dir.is_dir() and self.postgresql_dir.is_dir()

    def setup(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        self.generic_config.generic_setup()

    def purge_server(self) -> None:
        # Purge PostgreSQL (equivalent to Redis MEMORY PURGE)
        purge_postgresql = subprocess.run([
            "psql", "-U", "ycsbuser", "-h", "localhost", "-p", "5433", "-d", "ycsb",
            "-c", "TRUNCATE TABLE usertable;"
        ])
        if purge_postgresql.returncode != 0:
            raise BenchmarkError("PostgreSQL Failed To Purge")

    def run(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        if self.server is not None:
            raise BenchmarkRunningError()

        # Start our own PostgreSQL server (like Redis does)
        start_postgresql = [
            "/usr/lib/postgresql/*/bin/postgres",
            "-D", str(self.postgresql_dir / "data"),
            "-c", f"config_file={self.postgresql_dir}/postgresql.conf"
        ]
        # Use shell=True to handle the wildcard
        self.server = subprocess.Popen(" ".join(start_postgresql), shell=True)

        # Wait for PostgreSQL to start
        ping_postgresql = subprocess.run([
            "pg_isready", "-h", "localhost", "-p", "5433"
        ])
        i = 0
        while i < 10 and ping_postgresql.returncode != 0:
            time.sleep(1)
            ping_postgresql = subprocess.run([
                "pg_isready", "-h", "localhost", "-p", "5433"
            ])
            i += 1

        if ping_postgresql.returncode != 0:
            raise BenchmarkError("PostgreSQL Failed To Start")

        # Create database and user in our instance
        subprocess.run(["createdb", "-h", "localhost", "-p", "5433", "ycsb"])
        subprocess.run(["psql", "-h", "localhost", "-p", "5433", "-c", "CREATE USER ycsbuser WITH PASSWORD 'password';"])
        subprocess.run(["psql", "-h", "localhost", "-p", "5433", "-c", "GRANT ALL PRIVILEGES ON DATABASE ycsb TO ycsbuser;"])

        server_space: int | float | None = None if self.config.server_sleep is None else timeparse(self.config.server_sleep)
        if server_space is not None:
            time.sleep(server_space)

        space: int | float | None = None if self.config.sleep is None else timeparse(self.config.sleep)
        process: subprocess.Popen | None = None

        for out_i in range(self.config.outer_repeat):
            for i in range(self.config.repeat):
                if process is not None:
                    process.wait()
                    if self.config.explicit_purge:
                        self.purge_server()
                    if space is not None:
                        time.sleep(space)
                    if process.returncode != 0:
                        self.process = process
                        raise BenchmarkError(f"PostgreSQL Run {(2 * i) - 1} Failed")

                insert_start = out_i * self.config.record_count

                # Load Server (exactly like Redis pattern)
                load_postgresql = [
                    "python",
                    f"{self.benchmark_dir}/YCSB/bin/ycsb",
                    "load",
                    "jdbc",
                    "-s",
                    "-P",
                    f"{self.benchmark_dir}/YCSB/workloads/workloada",
                    "-p",
                    "db.driver=org.postgresql.Driver",
                    "-p",
                    "db.url=jdbc:postgresql://localhost:5433/ycsb",
                    "-p",
                    "db.user=ycsbuser",
                    "-p",
                    "db.passwd=password",
                    "-p",
                    f"recordcount={self.config.record_count}",
                    "-p",
                    f"fieldcount={self.config.field_count}",
                    "-p",
                    f"fieldlength={self.config.field_length}",
                    "-p",
                    f"minfieldlength={self.config.min_field_length}",
                    "-p",
                    f"insertstart={insert_start}",
                    "-p",
                    f"fieldlengthdistribution={self.config.field_length_distribution}",
                ]

                if i == 0:
                    load_postgresql = subprocess.Popen(load_postgresql, preexec_fn=demote())
                    load_postgresql.wait()
                    if load_postgresql.returncode != 0:
                        raise BenchmarkError("Loading PostgreSQL Failed")

                    if self.config.explicit_purge:
                        self.purge_server()

                subprocess.run(size_postgresql)

                record_count = (out_i + 1) * self.config.record_count

                # Run benchmark
                run_postgresql = [
                    f"{self.benchmark_dir}/YCSB/bin/ycsb",
                    "run",
                    "jdbc",
                    "-s",
                    "-P",
                    f"{self.benchmark_dir}/YCSB/workloads/workloada",
                    "-p",
                    f"operationcount={self.config.operation_count}",
                    "-p",
                    f"recordcount={record_count}",
                    "-p",
                    "workload=site.ycsb.workloads.CoreWorkload",
                    "-p",
                    f"readproportion={self.config.read_proportion}",
                    "-p",
                    f"updateproportion={self.config.update_proportion}",
                    "-p",
                    f"scanproportion={self.config.scan_proportion}",
                    "-p",
                    f"insertproportion={self.config.insert_proportion}",
                    "-p",
                    f"readmodifywriteproportion={self.config.rmw_proportion}",
                    "-p",
                    f"deleteproportion={self.config.delete_proportion}",
                    "-p",
                    "db.driver=org.postgresql.Driver",
                    "-p",
                    "db.url=jdbc:postgresql://localhost:5433/ycsb",
                    "-p",
                    "db.user=ycsbuser",
                    "-p",
                    "db.passwd=password",
                    "-p",
                    f"requestdistribution={self.config.request_distribution}",
                    "-p",
                    f"threadcount={self.config.thread_count}",
                    "-p",
                    f"target={self.config.target}",
                    "-p",
                    f"fieldcount={self.config.field_count}",
                    "-p",
                    f"fieldlength={self.config.field_length}",
                    "-p",
                    f"minfieldlength={self.config.min_field_length}",
                    "-p",
                    f"fieldlengthdistribution={self.config.field_length_distribution}",
                ]
                process = subprocess.Popen(run_postgresql, preexec_fn=demote())

        self.process = process

    def poll(self) -> int | None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        ret = self.process.poll()
        if ret is None:
            return ret
        self.end_server()
        return ret

    def wait(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.wait()
        self.end_server()

    def kill(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.terminate()
        self.end_server()

    def end_server(self) -> None:
        if self.server is None:
            return
        subprocess.run(size_postgresql)
        self.server.send_signal(signal.SIGINT)
        try:
            self.server.wait(10)
        except subprocess.TimeoutExpired:
            self.server.terminate()

        self.server = None

    @classmethod
    def plot_events(cls, graph_engine: GraphEngine) -> None:
        if graph_engine.collection_data.benchmark != cls.name():
            raise BenchmarkNotInCollectionData()
