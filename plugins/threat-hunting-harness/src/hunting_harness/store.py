"""Atomic case changes shared by callers; SQLite is authoritative."""

import json
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar, cast

from .models import Record

T = TypeVar("T")


class Store:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.database = self.root / "cases.sqlite"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS query_index ("
                "case_id TEXT, id TEXT, status TEXT, fingerprint TEXT, "
                "PRIMARY KEY (case_id, id))"
            )
            db.execute("CREATE INDEX IF NOT EXISTS query_state ON query_index(case_id, status)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS candidate_index ("
                "case_id TEXT, indicator TEXT, selected INTEGER, "
                "PRIMARY KEY (case_id, indicator))"
            )
        os.chmod(self.database, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _index(db: sqlite3.Connection, case: Record) -> None:
        db.executemany(
            "INSERT OR REPLACE INTO query_index VALUES (?, ?, ?, ?)",
            [
                (case["id"], job["id"], job["status"], job.get("fingerprint"))
                for job in case["queries"]
            ],
        )
        db.executemany(
            "INSERT OR REPLACE INTO candidate_index VALUES (?, ?, ?)",
            [(case["id"], item["indicator"], item["selected"]) for item in case["candidates"]],
        )

    def create(self, case: Record) -> Record:
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES (?, ?)", (case["id"], json.dumps(case)))
            self._index(db, case)
        return case

    def read(self, case_id: str) -> Record:
        with self.connect() as db:
            row = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown case")
        return cast(Record, json.loads(row[0]))

    def change(self, case_id: str, update: Callable[[Record], T]) -> T:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown case")
            case = json.loads(row[0])
            result = update(case)
            db.execute("UPDATE cases SET data = ? WHERE id = ?", (json.dumps(case), case_id))
            self._index(db, case)
        return result

    def case_ids(self) -> list[str]:
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT id FROM cases ORDER BY id")]
