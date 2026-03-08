#!/usr/bin/env python3
"""Build star-schema tables from the curated vulnerability mart."""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data"
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from src.lineage.lineage_logger import log_lineage_event


PRIORITY_DIMENSIONS = [
    {"priority_key": 1, "priority_bucket": "low", "priority_rank": 1},
    {"priority_key": 2, "priority_bucket": "medium", "priority_rank": 2},
    {"priority_key": 3, "priority_bucket": "high", "priority_rank": 3},
    {"priority_key": 4, "priority_bucket": "critical", "priority_rank": 4},
]

SEVERITY_DIMENSIONS = [
    {"severity_key": 1, "cvss_severity": "LOW", "severity_rank": 1},
    {"severity_key": 2, "cvss_severity": "MEDIUM", "severity_rank": 2},
    {"severity_key": 3, "cvss_severity": "HIGH", "severity_rank": 3},
    {"severity_key": 4, "cvss_severity": "CRITICAL", "severity_rank": 4},
    {"severity_key": 5, "cvss_severity": "UNKNOWN", "severity_rank": 0},
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build dim_date and fact_vulnerability_risk from curated datasets."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Base data directory (default: <repo>/data).",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_parquet_if_available(path: Path, rows: list[dict[str, Any]]) -> bool:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception:
        return False

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path)
    return True


def parse_date_maybe(value: str) -> date | None:
    if not value:
        return None
    try:
        if "T" in value:
            return datetime.fromisoformat(value).date()
        return date.fromisoformat(value)
    except ValueError:
        return None


def date_key(value: date | None) -> int | None:
    if value is None:
        return None
    return int(value.strftime("%Y%m%d"))


def build_dim_date(dates: set[date]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in sorted(dates):
        rows.append(
            {
                "date_key": int(value.strftime("%Y%m%d")),
                "full_date": value.isoformat(),
                "year": value.year,
                "quarter": ((value.month - 1) // 3) + 1,
                "month": value.month,
                "month_name": value.strftime("%B"),
                "week_of_year": int(value.strftime("%V")),
                "day_of_month": value.day,
                "day_of_week": value.isoweekday(),
                "day_name": value.strftime("%A"),
            }
        )
    return rows


def build_product_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        cve_id = row.get("cve_id", "")
        if cve_id:
            counts[cve_id] = counts.get(cve_id, 0) + 1
    return counts


def to_float_or_none(value: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def to_bool(value: str) -> bool:
    return str(value).strip().lower() == "true"


def build_dim_priority() -> list[dict[str, Any]]:
    return PRIORITY_DIMENSIONS.copy()


def build_priority_lookup(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {row["priority_bucket"]: row["priority_key"] for row in rows}


def build_dim_severity() -> list[dict[str, Any]]:
    return SEVERITY_DIMENSIONS.copy()


def build_severity_lookup(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {row["cvss_severity"]: row["severity_key"] for row in rows}


def build_dim_cwe(
    vulnerability_rows: list[dict[str, str]], problem_type_rows: list[dict[str, str]]
) -> list[dict[str, Any]]:
    descriptions_by_cwe: dict[str, set[str]] = {}

    for row in problem_type_rows:
        cwe_id = (row.get("cwe_id") or "").strip()
        description = (row.get("description") or "").strip()
        if not cwe_id:
            continue
        descriptions_by_cwe.setdefault(cwe_id, set())
        if description:
            descriptions_by_cwe[cwe_id].add(description)

    cwe_ids = {
        (row.get("cwe_id") or "").strip()
        for row in vulnerability_rows
        if (row.get("cwe_id") or "").strip()
    }
    cwe_ids.update(descriptions_by_cwe.keys())

    rows: list[dict[str, Any]] = []
    for cwe_id in sorted(cwe_ids):
        descriptions = sorted(descriptions_by_cwe.get(cwe_id, set()))
        rows.append(
            {
                "cwe_key": cwe_id,
                "cwe_name": cwe_id,
                "cwe_description": " | ".join(descriptions),
            }
        )
    return rows


def build_fact_rows(
    vulnerability_rows: list[dict[str, str]],
    product_counts: dict[str, int],
    priority_lookup: dict[str, int],
    severity_lookup: dict[str, int],
) -> tuple[list[dict[str, Any]], set[date]]:
    snapshot_day = datetime.now(UTC).date()
    snapshot_key = date_key(snapshot_day)
    dates: set[date] = {snapshot_day}
    rows: list[dict[str, Any]] = []

    for index, row in enumerate(vulnerability_rows, start=1):
        published_date = parse_date_maybe(row.get("published", ""))
        last_modified_date = parse_date_maybe(row.get("last_modified", ""))
        kev_date_added = parse_date_maybe(row.get("kev_date_added", ""))
        kev_due_date = parse_date_maybe(row.get("kev_due_date", ""))

        for item in (published_date, last_modified_date, kev_date_added, kev_due_date):
            if item is not None:
                dates.add(item)

        cve_id = row["cve_id"]
        rows.append(
            {
                "fact_id": index,
                "cve_id": cve_id,
                "snapshot_date_key": snapshot_key,
                "published_date_key": date_key(published_date),
                "last_modified_date_key": date_key(last_modified_date),
                "kev_date_added_key": date_key(kev_date_added),
                "kev_due_date_key": date_key(kev_due_date),
                "cwe_key": row.get("cwe_id", ""),
                "priority_key": priority_lookup.get(row.get("priority_bucket", ""), 1),
                "severity_key": severity_lookup.get(row.get("cvss_severity", ""), 5),
                "cwe_id": row.get("cwe_id", ""),
                "vendor": row.get("vendor", ""),
                "product": row.get("product", ""),
                "vuln_status": row.get("vuln_status", ""),
                "cvss_version": row.get("cvss_version", ""),
                "cvss_severity": row.get("cvss_severity", ""),
                "priority_bucket": row.get("priority_bucket", ""),
                "kev_ransomware_use": row.get("kev_ransomware_use", ""),
                "cvss_base_score": to_float_or_none(row.get("cvss_base_score", "")),
                "epss_score": to_float_or_none(row.get("epss_score", "")),
                "epss_percentile": to_float_or_none(row.get("epss_percentile", "")),
                "kev_flag": to_bool(row.get("in_kev", "")),
                "vulnerable_product_count": product_counts.get(cve_id, 0),
            }
        )

    return rows, dates


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)

    vulnerability_path = (
        data_dir / "curated" / "vulnerability_priority" / "vulnerability_priority_latest.csv"
    )
    bridge_path = data_dir / "curated" / "product_impact" / "bridge_cve_products_latest.csv"
    problem_types_path = (
        data_dir / "curated" / "cve_records" / "bridge_cve_problem_types_latest.csv"
    )

    curated_dir = data_dir / "curated" / "star_schema"
    curated_dir.mkdir(parents=True, exist_ok=True)

    dim_date_csv = curated_dir / "dim_date_latest.csv"
    dim_priority_csv = curated_dir / "dim_priority_latest.csv"
    dim_severity_csv = curated_dir / "dim_severity_latest.csv"
    dim_cwe_csv = curated_dir / "dim_cwe_latest.csv"
    fact_csv = curated_dir / "fact_vulnerability_risk_latest.csv"
    input_paths = [vulnerability_path, bridge_path, problem_types_path]
    output_paths = [
        dim_date_csv,
        dim_priority_csv,
        dim_severity_csv,
        dim_cwe_csv,
        fact_csv,
        curated_dir / "dim_date_latest.parquet",
        curated_dir / "dim_priority_latest.parquet",
        curated_dir / "dim_severity_latest.parquet",
        curated_dir / "dim_cwe_latest.parquet",
        curated_dir / "fact_vulnerability_risk_latest.parquet",
    ]

    try:
        vulnerability_rows = read_csv(vulnerability_path)
        bridge_rows = read_csv(bridge_path) if bridge_path.exists() else []
        problem_type_rows = read_csv(problem_types_path) if problem_types_path.exists() else []
        product_counts = build_product_counts(bridge_rows)
        dim_priority_rows = build_dim_priority()
        dim_severity_rows = build_dim_severity()
        dim_cwe_rows = build_dim_cwe(vulnerability_rows, problem_type_rows)

        fact_rows, dates = build_fact_rows(
            vulnerability_rows,
            product_counts,
            build_priority_lookup(dim_priority_rows),
            build_severity_lookup(dim_severity_rows),
        )
        dim_date_rows = build_dim_date(dates)

        write_csv(dim_date_csv, dim_date_rows)
        write_csv(dim_priority_csv, dim_priority_rows)
        write_csv(dim_severity_csv, dim_severity_rows)
        write_csv(dim_cwe_csv, dim_cwe_rows)
        write_csv(fact_csv, fact_rows)

        dim_date_parquet = write_parquet_if_available(curated_dir / "dim_date_latest.parquet", dim_date_rows)
        dim_priority_parquet = write_parquet_if_available(
            curated_dir / "dim_priority_latest.parquet", dim_priority_rows
        )
        dim_severity_parquet = write_parquet_if_available(
            curated_dir / "dim_severity_latest.parquet", dim_severity_rows
        )
        dim_cwe_parquet = write_parquet_if_available(curated_dir / "dim_cwe_latest.parquet", dim_cwe_rows)
        fact_parquet = write_parquet_if_available(
            curated_dir / "fact_vulnerability_risk_latest.parquet", fact_rows
        )

        print(f"Built dim_date rows: {len(dim_date_rows)}")
        print(f"Built dim_priority rows: {len(dim_priority_rows)}")
        print(f"Built dim_severity rows: {len(dim_severity_rows)}")
        print(f"Built dim_cwe rows: {len(dim_cwe_rows)}")
        print(f"Built fact_vulnerability_risk rows: {len(fact_rows)}")
        print(f"dim_date CSV: {dim_date_csv}")
        print(f"dim_priority CSV: {dim_priority_csv}")
        print(f"dim_severity CSV: {dim_severity_csv}")
        print(f"dim_cwe CSV: {dim_cwe_csv}")
        print(f"fact_vulnerability_risk CSV: {fact_csv}")
        if dim_date_parquet and dim_priority_parquet and dim_severity_parquet and dim_cwe_parquet and fact_parquet:
            print("Parquet outputs created for star schema tables")
        else:
            print("Parquet skipped for one or more star schema tables: pyarrow not installed")

        log_lineage_event(
            data_dir=data_dir,
            job_name="build_star_schema",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Build dim_date/dim_priority/dim_severity/dim_cwe and fact_vulnerability_risk.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="success",
            input_count=len(vulnerability_rows),
            output_count=len(fact_rows),
        )
        return 0
    except Exception as exc:
        log_lineage_event(
            data_dir=data_dir,
            job_name="build_star_schema",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Build dim_date/dim_priority/dim_severity/dim_cwe and fact_vulnerability_risk.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="failed",
            error_message=str(exc),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
