#!/usr/bin/env python3
"""Build product dimension and CVE-product bridge tables from NVD raw data."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data"
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from src.lineage.lineage_logger import log_lineage_event


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract product-level bridge tables from raw NVD vulnerability data."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Base data directory (default: <repo>/data).",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_parquet_if_available(path: Path, rows: list[dict[str, Any]]) -> bool:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception:
        return False

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path)
    return True


def extract_products(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    product_map: dict[str, dict[str, Any]] = {}
    bridge_rows: list[dict[str, Any]] = []

    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                operator = node.get("operator", "")
                negate = bool(node.get("negate", False))
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
                        continue

                    product_key = criteria
                    vendor = parts[3]
                    product = parts[4]
                    product_version = parts[5]
                    cpe_part = parts[2]
                    target_sw = parts[10]
                    target_hw = parts[11]

                    product_map[product_key] = {
                        "product_key": product_key,
                        "cpe_uri": criteria,
                        "cpe_part": cpe_part,
                        "vendor": vendor,
                        "product": product,
                        "product_version": product_version,
                        "target_software": target_sw,
                        "target_hardware": target_hw,
                    }

                    bridge_rows.append(
                        {
                            "cve_id": cve_id,
                            "product_key": product_key,
                            "vendor": vendor,
                            "product": product,
                            "is_vulnerable": bool(match.get("vulnerable", False)),
                            "version_start_including": match.get("versionStartIncluding", ""),
                            "version_start_excluding": match.get("versionStartExcluding", ""),
                            "version_end_including": match.get("versionEndIncluding", ""),
                            "version_end_excluding": match.get("versionEndExcluding", ""),
                            "match_criteria_id": match.get("matchCriteriaId", ""),
                            "node_operator": operator,
                            "node_negate": negate,
                        }
                    )

    products = sorted(product_map.values(), key=lambda row: row["product_key"])
    bridge_rows.sort(key=lambda row: (row["cve_id"], row["product_key"]))
    return products, bridge_rows


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    nvd_path = data_dir / "raw" / "nvd" / "nvdcve-2.0-2026.json"
    payload = load_json(nvd_path)

    products, bridge_rows = extract_products(payload)

    staging_dir = data_dir / "staging" / "nvd_products"
    curated_dir = data_dir / "curated" / "product_impact"
    staging_dir.mkdir(parents=True, exist_ok=True)
    curated_dir.mkdir(parents=True, exist_ok=True)

    product_dim_csv = curated_dir / "dim_products_latest.csv"
    bridge_csv = curated_dir / "bridge_cve_products_latest.csv"
    bridge_jsonl = staging_dir / "bridge_cve_products_latest.jsonl"
    product_parquet = curated_dir / "dim_products_latest.parquet"
    bridge_parquet = curated_dir / "bridge_cve_products_latest.parquet"
    input_paths = [nvd_path]
    output_paths = [product_dim_csv, bridge_csv, bridge_jsonl, product_parquet, bridge_parquet]

    try:
        write_csv(product_dim_csv, products)
        write_csv(bridge_csv, bridge_rows)
        write_jsonl(bridge_jsonl, bridge_rows)
        products_parquet = write_parquet_if_available(product_parquet, products)
        bridge_parquet_written = write_parquet_if_available(bridge_parquet, bridge_rows)

        print(f"Built product dimension rows: {len(products)}")
        print(f"Built CVE-product bridge rows: {len(bridge_rows)}")
        print(f"Product dimension CSV: {product_dim_csv}")
        print(f"Bridge CSV: {bridge_csv}")
        print(f"Bridge JSONL: {bridge_jsonl}")
        if products_parquet and bridge_parquet_written:
            print(f"Product dimension Parquet: {product_parquet}")
            print(f"Bridge Parquet: {bridge_parquet}")
        else:
            print("Parquet skipped: pyarrow not installed")

        log_lineage_event(
            data_dir=data_dir,
            job_name="build_cve_product_bridge",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Extract product dimension and CVE-product bridge from NVD configurations.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="success",
            input_count=len(payload.get("vulnerabilities", [])),
            output_count=len(bridge_rows),
        )
        return 0
    except Exception as exc:
        log_lineage_event(
            data_dir=data_dir,
            job_name="build_cve_product_bridge",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Extract product dimension and CVE-product bridge from NVD configurations.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="failed",
            error_message=str(exc),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
