import polars as pl
from data_schema.schema import CollectionTable


class VFSReadDataTable(CollectionTable):
    """Schema for vfs_read trace data"""

    @classmethod
    def name(cls) -> str:
        return "vfs_read"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "pid": pl.Int64(),
            "tgid": pl.Int64(),
            "comm": pl.String(),
            "count": pl.Int64(),
            "buf": pl.Int64(),
            "ret": pl.Int64(),
            "which_read": pl.Int64(),  # 1 = .read, 2 = .read_iter
            "success": pl.Int64(),     # 1 = read succeeded, 0 = failed
            "ts_ns": pl.Int64(),
            "collection_id": pl.String(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "VFSReadDataTable":
        return VFSReadDataTable(table=table.cast(cls.schema(), strict=True))  # pyright: ignore

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self._table

    def graphs(self) -> list:
        return []
