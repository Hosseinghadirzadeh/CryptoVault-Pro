from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Operation:
    timestamp: str
    action: str
    item: str
    algorithm: str
    status: str


class HistoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def list(self, limit: int = 100) -> list[Operation]:
        try:
            records = json.loads(self.path.read_text(encoding="utf-8"))
            return [Operation(**record) for record in records[-limit:]][::-1]
        except (FileNotFoundError, json.JSONDecodeError, TypeError, KeyError):
            return []

    def add(self, action: str, item: str, algorithm: str, status: str = "Success") -> None:
        records = self.list(500)[::-1]
        records.append(Operation(datetime.now(timezone.utc).isoformat(timespec="seconds"), action, Path(item).name, algorithm, status))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(record) for record in records[-500:]], indent=2), encoding="utf-8")

    def export(self, destination: str | Path) -> None:
        destination = Path(destination)
        lines = ["timestamp,action,item,algorithm,status"]
        for record in self.list(500)[::-1]:
            fields = (record.timestamp, record.action, record.item, record.algorithm, record.status)
            lines.append(",".join('"' + value.replace('"', '""') + '"' for value in fields))
        destination.write_text("\n".join(lines), encoding="utf-8")

