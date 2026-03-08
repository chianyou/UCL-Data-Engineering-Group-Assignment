#!/usr/bin/env python3
"""Build summary datasets for the transformation owner deliverables."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data"
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from src.lineage.lineage_logger import log_lineage_event
HIGH_EPSS_THRESHOLD = 0.7


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build summary transformation datasets from curated vulnerability data."
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


def to_float_or_none(value: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def to_bool(value: str) -> bool:
    return str(value).strip().lower() == "true"


def iso_date_only(value: str) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value).date().isoformat()
    except ValueError:
        return value.split("T", 1)[0]


def build_daily_new_cves(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        published_date = iso_date_only(row.get("published", ""))
        if published_date:
            counts[published_date] += 1
    return [
        {"published_date": published_date, "new_cve_count": counts[published_date]}
        for published_date in sorted(counts)
    ]


def build_cvss_distribution(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        severity = (row.get("cvss_severity") or "UNKNOWN").strip() or "UNKNOWN"
        counts[severity] += 1
    return [
        {"cvss_severity": severity, "cve_count": counts[severity]}
        for severity in sorted(counts)
    ]


def build_kev_hit_rate(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"total_cves": 0, "kev_cves": 0})
    for row in rows:
        severity = (row.get("cvss_severity") or "UNKNOWN").strip() or "UNKNOWN"
        stats[severity]["total_cves"] += 1
        if to_bool(row.get("in_kev", "")):
            stats[severity]["kev_cves"] += 1

    output: list[dict[str, Any]] = []
    for severity in sorted(stats):
        total = stats[severity]["total_cves"]
        kev = stats[severity]["kev_cves"]
        output.append(
            {
                "cvss_severity": severity,
                "total_cves": total,
                "kev_cves": kev,
                "kev_hit_rate": round(kev / total, 6) if total else 0.0,
            }
        )
    return output


def build_epss_high_risk_distribution(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    stats: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"total_cves": 0, "high_epss_cves": 0, "sum_epss_score": 0.0, "scored_cves": 0}
    )
    for row in rows:
        key = (row.get("vendor", ""), row.get("product", ""))
        stats[key]["total_cves"] += 1
        epss_score = to_float_or_none(row.get("epss_score", ""))
        if epss_score is not None:
            stats[key]["sum_epss_score"] += epss_score
            stats[key]["scored_cves"] += 1
            if epss_score >= HIGH_EPSS_THRESHOLD:
                stats[key]["high_epss_cves"] += 1

    output: list[dict[str, Any]] = []
    for (vendor, product), values in sorted(
        stats.items(), key=lambda item: (-item[1]["high_epss_cves"], -item[1]["total_cves"], item[0])
    ):
        total = values["total_cves"]
        high = values["high_epss_cves"]
        scored = values["scored_cves"]
        output.append(
            {
                "vendor": vendor,
                "product": product,
                "total_cves": total,
                "scored_cves": scored,
                "high_epss_cves": high,
                "high_epss_rate": round(high / total, 6) if total else 0.0,
                "avg_epss_score": round(values["sum_epss_score"] / scored, 6) if scored else None,
            }
        )
    return output


def build_bridge_enriched_rows(
    mart_rows: list[dict[str, str]], bridge_rows: list[dict[str, str]]
) -> list[dict[str, str]]:
    mart_by_cve = {row["cve_id"]: row for row in mart_rows if row.get("cve_id")}
    enriched_rows: list[dict[str, str]] = []

    for bridge_row in bridge_rows:
        cve_id = bridge_row.get("cve_id", "")
        mart_row = mart_by_cve.get(cve_id)
        if not mart_row:
            continue
        vendor = (bridge_row.get("vendor") or "").strip()
        product = (bridge_row.get("product") or "").strip()
        if not vendor or not product:
            continue

        enriched_rows.append(
            {
                **mart_row,
                "vendor": vendor,
                "product": product,
            }
        )

    return enriched_rows


def build_cwe_vendor_product_aggregation(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    stats: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
        lambda: {"cve_count": 0, "kev_cves": 0, "sum_epss_score": 0.0, "scored_cves": 0}
    )
    for row in rows:
        key = (row.get("cwe_id", ""), row.get("vendor", ""), row.get("product", ""))
        stats[key]["cve_count"] += 1
        if to_bool(row.get("in_kev", "")):
            stats[key]["kev_cves"] += 1
        epss_score = to_float_or_none(row.get("epss_score", ""))
        if epss_score is not None:
            stats[key]["sum_epss_score"] += epss_score
            stats[key]["scored_cves"] += 1

    output: list[dict[str, Any]] = []
    for (cwe_id, vendor, product), values in sorted(
        stats.items(), key=lambda item: (-item[1]["cve_count"], item[0])
    ):
        cve_count = values["cve_count"]
        kev_cves = values["kev_cves"]
        scored = values["scored_cves"]
        output.append(
            {
                "cwe_id": cwe_id,
                "vendor": vendor,
                "product": product,
                "cve_count": cve_count,
                "kev_cves": kev_cves,
                "kev_hit_rate": round(kev_cves / cve_count, 6) if cve_count else 0.0,
                "avg_epss_score": round(values["sum_epss_score"] / scored, 6) if scored else None,
            }
        )
    return output


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    mart_path = data_dir / "curated" / "vulnerability_priority" / "vulnerability_priority_latest.csv"
    bridge_path = data_dir / "curated" / "product_impact" / "bridge_cve_products_latest.csv"

    summary_dir = data_dir / "curated" / "transformation_summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)

    input_paths = [mart_path, bridge_path]
    output_paths: list[Path] = []
    output_row_count = 0

    try:
        mart_rows = read_csv(mart_path)
        bridge_rows = read_csv(bridge_path) if bridge_path.exists() else []
        bridge_enriched_rows = build_bridge_enriched_rows(mart_rows, bridge_rows)

        outputs = {
            "fact_daily_new_cves_latest": build_daily_new_cves(mart_rows),
            "agg_cvss_severity_distribution_latest": build_cvss_distribution(mart_rows),
            "agg_kev_hit_rate_by_cvss_severity_latest": build_kev_hit_rate(mart_rows),
            "agg_epss_high_risk_by_vendor_product_latest": build_epss_high_risk_distribution(
                bridge_enriched_rows
            ),
            "agg_cwe_vendor_product_latest": build_cwe_vendor_product_aggregation(bridge_enriched_rows),
        }

        parquet_written = True
        for name, rows in outputs.items():
            csv_path = summary_dir / f"{name}.csv"
            parquet_path = summary_dir / f"{name}.parquet"
            output_paths.extend([csv_path, parquet_path])
            write_csv(csv_path, rows)
            parquet_written = write_parquet_if_available(parquet_path, rows) and parquet_written
            output_row_count += len(rows)
            print(f"Built {name}: {len(rows)} rows")
            print(f"CSV: {csv_path}")

        if parquet_written:
            print("Parquet outputs created for all transformation summary datasets")
        else:
            print("Parquet skipped for one or more summary datasets: pyarrow not installed")

        log_lineage_event(
            data_dir=data_dir,
            job_name="build_transformation_summaries",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Build analytics summary aggregates for trend, severity, KEV, EPSS, and CWE views.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="success",
            input_count=len(mart_rows),
            output_count=output_row_count,
        )
        return 0
    except Exception as exc:
        log_lineage_event(
            data_dir=data_dir,
            job_name="build_transformation_summaries",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Build analytics summary aggregates for trend, severity, KEV, EPSS, and CWE views.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="failed",
            error_message=str(exc),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
