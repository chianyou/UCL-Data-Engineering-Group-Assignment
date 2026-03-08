#!/usr/bin/env python3
"""Minimal lineage logger for pipeline jobs."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


LINEAGE_FIELDS = [
    "run_id",
    "run_ts_utc",
    "job_name",
    "layer",
    "status",
    "code_path",
    "transform_summary",
    "input_count",
    "output_count",
    "error_message",
    "input_datasets",
    "output_datasets",
]


def _dataset_entry(path: Path) -> dict[str, Any]:
    exists = path.exists()
    item: dict[str, Any] = {
        "path": str(path.resolve()),
        "exists": exists,
    }
    if exists:
        stat = path.stat()
        item["size_bytes"] = stat.st_size
        item["modified_at_utc"] = datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()
    return item


def _append_csv(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LINEAGE_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def log_lineage_event(
    *,
    data_dir: Path,
    job_name: str,
    layer: str,
    code_path: Path,
    transform_summary: str,
    input_paths: list[Path],
    output_paths: list[Path],
    status: str,
    input_count: int | None = None,
    output_count: int | None = None,
    error_message: str = "",
) -> None:
    """Write a lineage event without interrupting the pipeline on logger failure."""
    try:
        lineage_dir = data_dir / "curated" / "lineage"
        run_id = uuid4().hex
        now = datetime.now(UTC).isoformat()

        inputs = [_dataset_entry(path) for path in input_paths]
        outputs = [_dataset_entry(path) for path in output_paths]

        csv_record = {
            "run_id": run_id,
            "run_ts_utc": now,
            "job_name": job_name,
            "layer": layer,
            "status": status,
            "code_path": str(code_path.resolve()),
            "transform_summary": transform_summary,
            "input_count": "" if input_count is None else input_count,
            "output_count": "" if output_count is None else output_count,
            "error_message": error_message,
            "input_datasets": json.dumps(inputs, ensure_ascii=False),
            "output_datasets": json.dumps(outputs, ensure_ascii=False),
        }
        jsonl_record = dict(csv_record)
        jsonl_record["input_datasets"] = inputs
        jsonl_record["output_datasets"] = outputs

        _append_csv(lineage_dir / "lineage_events_latest.csv", csv_record)
        _append_jsonl(lineage_dir / "lineage_events_latest.jsonl", jsonl_record)
    except Exception as exc:  # pragma: no cover - logging should never break jobs
        print(f"[lineage] warning: failed to write lineage event: {exc}")

