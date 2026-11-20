"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from tracemalloc import start


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        now = datetime.now(timezone.utc)
        key = request_id or user_id

        self._open[key] = {
            "start_ts": now.timestamp(),
            "text": text,
            "user_id": user_id,
        }
        self.logs.append(
            {
                "timestamp": now.isoformat(),
                "user_id": user_id,
                "request_id": request_id,
                "text": text,
                "blocked": False,
                "layer": "input",
            }
        )

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        now = datetime.now(timezone.utc)
        key = request_id or user_id
        entry = self._open.pop(key, None)
        start_ts = entry["start_ts"] if isinstance(entry, dict) else None

        latency_ms = (
            round((now.timestamp() - start_ts) * 1000, 2)
            if start_ts is not None
            else None
        )

        self.logs.append(
            {
                "timestamp": now.isoformat(),
                "user_id": user_id,
                "request_id": request_id,
                "text": text,
                "blocked": blocked,
                "layer": layer or "output",
                "latency_ms": latency_ms,
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)      


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
