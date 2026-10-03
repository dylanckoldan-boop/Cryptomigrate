"""Data-source adapters used by discovery profiling, re-encryption, rollback and verification.

* ``SQLAdapter``  - any PEP 249 (DB-API 2.0) driver: sqlite3, psycopg/psycopg2, pymysql,
                    mysql.connector, oracledb, pyodbc... Placeholders follow the driver's
                    ``paramstyle``; identifiers are validated at config load (no injection via
                    config). Keyset pagination on a single-column primary key.
* ``FileAdapter`` - encrypted files under a directory, rewritten atomically.

Write a new adapter by implementing the same small surface (see docs/EXTENDING.md).
"""

from __future__ import annotations

import importlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DataSource, resolve_env_refs

FILE_FIELD = "<file>"


@dataclass
class Target:
    name: str
    legacy_profile: str
    storage: str  # text | blob
    max_length: int | None = None


class SQLAdapter:
    kind = "sql"

    def __init__(self, ds: DataSource):
        self.ds = ds
        try:
            self.module = importlib.import_module(ds.driver)
        except ImportError as exc:
            raise RuntimeError(f"data source {ds.name}: cannot import DB-API driver {ds.driver!r}: {exc}") from exc
        self.paramstyle = getattr(self.module, "paramstyle", "qmark")
        self.conn = self.module.connect(**resolve_env_refs(ds.connect))

    # -------------------------------------------------------------- plumbing
    def __enter__(self) -> SQLAdapter:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001,S110 - closing must never mask the real error
            pass

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def _bind(self, values: list[Any]) -> tuple[list[str], Any]:
        style = self.paramstyle
        if style == "qmark":
            return ["?"] * len(values), tuple(values)
        if style == "numeric":
            return [f":{i + 1}" for i in range(len(values))], tuple(values)
        if style == "named":
            return [f":p{i}" for i in range(len(values))], {f"p{i}": v for i, v in enumerate(values)}
        if style in ("format", "pyformat"):
            return ["%s"] * len(values), tuple(values)
        raise RuntimeError(f"unsupported DB-API paramstyle {style!r}")

    def _execute(self, sql: str, params: Any = ()):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def _select(self, columns: str, where: str, order: str, limit: int) -> str:
        t = self.ds.table
        style = self.ds.limit_style
        if style == "top":
            return f"SELECT TOP {int(limit)} {columns} FROM {t}{where}{order}"  # noqa: S608 - validated identifiers
        tail = f" FETCH FIRST {int(limit)} ROWS ONLY" if style == "fetch" else f" LIMIT {int(limit)}"
        return f"SELECT {columns} FROM {t}{where}{order}{tail}"  # noqa: S608 - validated identifiers

    # ---------------------------------------------------------------- reading
    def targets(self) -> list[Target]:
        return [Target(c.name, c.legacy_profile, c.storage, c.max_length) for c in self.ds.columns]

    def count(self) -> int:
        return int(self._execute(f"SELECT COUNT(*) FROM {self.ds.table}").fetchone()[0])  # noqa: S608

    def batches(self, after: Any = None, size: int = 500):
        """Yield lists of (pk, {column: value}) using keyset pagination - restartable from ``after``."""
        pk = self.ds.primary_key
        cols = [c.name for c in self.ds.columns]
        while True:
            if after is None:
                sql, params = self._select(", ".join([pk, *cols]), "", f" ORDER BY {pk}", size), ()
            else:
                ph, params = self._bind([after])
                sql = self._select(", ".join([pk, *cols]), f" WHERE {pk} > {ph[0]}", f" ORDER BY {pk}", size)
            rows = self._execute(sql, params).fetchall()
            if not rows:
                return
            yield [(row[0], dict(zip(cols, row[1:], strict=True))) for row in rows]
            after = rows[-1][0]
            if len(rows) < size:
                return

    def sample(self, column: str, n: int) -> list[Any]:
        sql = self._select(column, f" WHERE {column} IS NOT NULL", f" ORDER BY {self.ds.primary_key}", n)
        return [row[0] for row in self._execute(sql).fetchall()]

    def fetch(self, pks: list[Any], column: str) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        for i in range(0, len(pks), 500):
            chunk = pks[i:i + 500]
            ph, params = self._bind(chunk)
            sql = (f"SELECT {self.ds.primary_key}, {column} FROM {self.ds.table} "  # noqa: S608
                   f"WHERE {self.ds.primary_key} IN ({', '.join(ph)})")
            out.update({row[0]: row[1] for row in self._execute(sql, params).fetchall()})
        return out

    # ---------------------------------------------------------------- writing
    def update_cas(self, pk: Any, column: str, old: Any, new: Any) -> bool:
        """Compare-and-swap: only overwrite if the value is still what we read (online-migration safe)."""
        ph, params = self._bind([new, pk, old])
        sql = (f"UPDATE {self.ds.table} SET {column} = {ph[0]} "  # noqa: S608 - validated identifiers
               f"WHERE {self.ds.primary_key} = {ph[1]} AND {column} = {ph[2]}")
        return self._execute(sql, params).rowcount == 1

    def context(self, column: str, pk: Any) -> str:
        return self.ds.render_aad(column=column, pk=pk)


class FileAdapter:
    kind = "files"

    def __init__(self, ds: DataSource):
        self.ds = ds
        self.base = Path(ds.path)
        if not self.base.is_dir():
            raise RuntimeError(f"data source {ds.name}: directory not found: {self.base}")

    def __enter__(self) -> FileAdapter:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def close(self) -> None:
        return None

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def targets(self) -> list[Target]:
        return [Target(FILE_FIELD, self.ds.legacy_profile or "", "blob", None)]

    def files(self) -> list[str]:
        out = []
        for path in self.base.glob(self.ds.glob):
            if path.is_file() and not path.name.startswith(".") and ".cm-tmp-" not in path.name:
                out.append(path.relative_to(self.base).as_posix())
        return sorted(out)

    def count(self) -> int:
        return len(self.files())

    def sample(self, column: str, n: int) -> list[bytes]:
        return [self.read(rel) for rel in self.files()[:n]]

    def read(self, rel: str) -> bytes:
        return (self.base / rel).read_bytes()

    def write_atomic(self, rel: str, data: bytes, expected: bytes | None = None) -> bool:
        path = self.base / rel
        if expected is not None and path.read_bytes() != expected:
            return False  # changed underneath us - skip, never clobber
        tmp = path.with_name(f".{path.name}.cm-tmp-{os.getpid()}")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
        return True

    def context(self, column: str, rel: str) -> str:
        return self.ds.render_aad(column=column, relpath=rel)


def open_adapter(ds: DataSource) -> SQLAdapter | FileAdapter:
    return SQLAdapter(ds) if ds.adapter == "sql" else FileAdapter(ds)
