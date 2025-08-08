import polars as pl
from data_schema.schema import CollectionTable


class VFSWriteDataTable(CollectionTable):
    """Schema for vfs_write trace data"""

    @classmethod
    def name(cls) -> str:
        return "vfs_write"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "pid": pl.Int64(),
            "tgid": pl.Int64(),
            "comm": pl.String(),
            "count": pl.Int64(),
            "buf": pl.Int64(),
            "ret": pl.Int64(),
            "which_write": pl.Int64(),  # 1 = .write, 2 = .write_iter
            "success": pl.Int64(),      # 1 = write succeeded, 0 = failed
            "ts_ns": pl.Int64(),
            "collection_id": pl.String(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "VFSWriteDataTable":
        return VFSWriteDataTable(table=table.cast(cls.schema(), strict=True))  # pyright: ignore

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self._table

    def graphs(self) -> list:
        return []
