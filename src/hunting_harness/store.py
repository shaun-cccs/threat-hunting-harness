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
            db.execute(
                "CREATE TABLE IF NOT EXISTS evidence_raw ("
                "case_id TEXT NOT NULL, evidence_id TEXT NOT NULL, raw TEXT NOT NULL, "
                "PRIMARY KEY (case_id, evidence_id))"
            )
            self._migrate(db)
        os.chmod(self.database, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    SCHEMA_VERSION = 1
    PARAMETER_LIMIT = 500

    @staticmethod
    def _split(
        db: sqlite3.Connection,
        case_id: str,
        case: Record,
        skip: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        """Move retained payloads out of the case document and into their own rows.

        Evidence read back from storage carries no `raw`, so only newly appended records — and
        records deliberately hydrated for this change — hold one here. Payloads already stored are
        left untouched, which is what keeps a change off the whole retained volume.
        """
        pending = [
            (case_id, item["id"], json.dumps(item.pop("raw")))
            for item in case.get("evidence", [])
            if "raw" in item and item["id"] not in skip
        ]
        for item in case.get("evidence", []):
            item.pop("raw", None)
        if pending:
            db.executemany("INSERT OR REPLACE INTO evidence_raw VALUES (?, ?, ?)", pending)

    def _payloads(
        self, db: sqlite3.Connection, case_id: str, evidence_ids: list[str] | None
    ) -> dict[str, Record]:
        if evidence_ids is None:
            rows = db.execute(
                "SELECT evidence_id, raw FROM evidence_raw WHERE case_id = ?", (case_id,)
            ).fetchall()
            return {row[0]: json.loads(row[1]) for row in rows}
        wanted = list(dict.fromkeys(evidence_ids))
        found: dict[str, Record] = {}
        for start in range(0, len(wanted), self.PARAMETER_LIMIT):
            batch = wanted[start : start + self.PARAMETER_LIMIT]
            placeholders = ", ".join("?" * len(batch))
            rows = db.execute(
                "SELECT evidence_id, raw FROM evidence_raw "
                f"WHERE case_id = ? AND evidence_id IN ({placeholders})",
                (case_id, *batch),
            ).fetchall()
            found.update({row[0]: json.loads(row[1]) for row in rows})
        return found

    def _migrate(self, db: sqlite3.Connection) -> None:
        """Move inline payloads out of cases written before payloads had their own table.

        One transaction covers every case and the version stamp together, so an interrupted
        upgrade rolls back whole and re-runs cleanly rather than leaving a half-split case.
        """
        if db.execute("PRAGMA user_version").fetchone()[0] >= self.SCHEMA_VERSION:
            return
        for row in db.execute("SELECT id FROM cases ORDER BY id").fetchall():
            case_id = row[0]
            stored = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            case = json.loads(stored[0])
            if any("raw" in item for item in case.get("evidence", [])):
                self._split(db, case_id, case)
                db.execute("UPDATE cases SET data = ? WHERE id = ?", (json.dumps(case), case_id))
            del case
        db.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")

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
            self._split(db, case["id"], case)
            db.execute("INSERT INTO cases VALUES (?, ?)", (case["id"], json.dumps(case)))
            self._index(db, case)
        return case

    def read(self, case_id: str) -> Record:
        """The case without retained payloads; fetch those with `read_raw` when they are needed.

        This is the hot path: every disposition, status read and job completion goes through it,
        so it must not carry the retained provider volume, which dwarfs everything else in a
        grown case.
        """
        with self.connect() as db:
            row = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown case")
        case = cast(Record, json.loads(row[0]))
        for item in case.get("evidence", []):
            item.pop("raw", None)
        return case

    def read_raw(self, case_id: str, evidence_ids: list[str] | None = None) -> dict[str, Record]:
        """Retained payloads by evidence ID, batched; all of them when no IDs are given."""
        with self.connect() as db:
            return self._payloads(db, case_id, evidence_ids)

    def change(
        self,
        case_id: str,
        update: Callable[[Record], T],
        hydrate: Callable[[Record], list[str] | None] | None = None,
    ) -> T:
        """Apply one atomic change, splitting retained payloads out at commit.

        `hydrate` names the evidence whose payloads the change itself has to read, resolved
        against the decoded case because a caller cannot know a candidate's evidence IDs before
        reading it. Splitting after `update` keeps the payload write inside this transaction, so
        a case and its payloads cannot diverge.
        """
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown case")
            case = json.loads(row[0])
            for item in case.get("evidence", []):
                item.pop("raw", None)
            attached: set[str] = set()
            if hydrate is not None:
                payloads = self._payloads(db, case_id, hydrate(case))
                for item in case.get("evidence", []):
                    if item["id"] in payloads:
                        item["raw"] = payloads[item["id"]]
                        attached.add(item["id"])
            result = update(case)
            self._split(db, case_id, case, attached)
            db.execute("UPDATE cases SET data = ? WHERE id = ?", (json.dumps(case), case_id))
            self._index(db, case)
        return result

    def case_ids(self) -> list[str]:
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT id FROM cases ORDER BY id")]
