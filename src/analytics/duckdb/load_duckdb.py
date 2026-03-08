#!/usr/bin/env python3
"""Load curated Parquet datasets into a local DuckDB database."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import duckdb

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "analytics.duckdb"
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "curated"
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from src.lineage.lineage_logger import log_lineage_event


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load curated Parquet datasets into DuckDB tables."
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help="DuckDB file path (default: <repo>/data/analytics.duckdb).",
    )
    parser.add_argument(
        "--curated-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Curated data directory (default: <repo>/data/curated).",
    )
    return parser.parse_args()


def create_table_from_parquet(connection: duckdb.DuckDBPyConnection, table_name: str, parquet_path: Path) -> None:
    connection.execute(
        f"""
        CREATE OR REPLACE TABLE {table_name} AS
        SELECT * FROM read_parquet(?)
        """,
        [str(parquet_path)],
    )


def main() -> int:
    args = parse_args()
    db_path = Path(args.db_path)
    curated_dir = Path(args.curated_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    table_map = {
        "vulnerability_priority": curated_dir
        / "vulnerability_priority"
        / "vulnerability_priority_latest.parquet",
        "dim_products": curated_dir / "product_impact" / "dim_products_latest.parquet",
        "bridge_cve_products": curated_dir
        / "product_impact"
        / "bridge_cve_products_latest.parquet",
        "dim_date": curated_dir / "star_schema" / "dim_date_latest.parquet",
        "dim_priority": curated_dir / "star_schema" / "dim_priority_latest.parquet",
        "dim_severity": curated_dir / "star_schema" / "dim_severity_latest.parquet",
        "dim_cwe": curated_dir / "star_schema" / "dim_cwe_latest.parquet",
        "fact_vulnerability_risk": curated_dir
        / "star_schema"
        / "fact_vulnerability_risk_latest.parquet",
        "agg_daily_new_cves": curated_dir
        / "transformation_summaries"
        / "fact_daily_new_cves_latest.parquet",
        "agg_cvss_severity_distribution": curated_dir
        / "transformation_summaries"
        / "agg_cvss_severity_distribution_latest.parquet",
        "agg_kev_hit_rate_by_cvss_severity": curated_dir
        / "transformation_summaries"
        / "agg_kev_hit_rate_by_cvss_severity_latest.parquet",
        "agg_epss_by_vendor_product": curated_dir
        / "transformation_summaries"
        / "agg_epss_high_risk_by_vendor_product_latest.parquet",
        "agg_cwe_vendor_product": curated_dir
        / "transformation_summaries"
        / "agg_cwe_vendor_product_latest.parquet",
    }

    input_paths = list(table_map.values())
    output_paths = [db_path]
    output_count = 0

    try:
        missing = [name for name, path in table_map.items() if not path.exists()]
        if missing:
            print("Missing input parquet files for tables:")
            for name in missing:
                print(f"- {name}: {table_map[name]}")
            log_lineage_event(
                data_dir=curated_dir.parent,
                job_name="load_duckdb_tables",
                layer="analytics",
                code_path=Path(__file__),
                transform_summary="Load curated parquet datasets into DuckDB analytics tables.",
                input_paths=input_paths,
                output_paths=output_paths,
                status="failed",
                error_message=f"Missing parquet inputs for {len(missing)} tables",
            )
            return 1

        with duckdb.connect(str(db_path)) as con:
            for table_name, parquet_path in table_map.items():
                create_table_from_parquet(con, table_name, parquet_path)
                count = con.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
                output_count += int(count)
                print(f"Loaded {table_name}: {count} rows")

        print(f"DuckDB database ready: {db_path.resolve()}")
        log_lineage_event(
            data_dir=curated_dir.parent,
            job_name="load_duckdb_tables",
            layer="analytics",
            code_path=Path(__file__),
            transform_summary="Load curated parquet datasets into DuckDB analytics tables.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="success",
            input_count=len(input_paths),
            output_count=output_count,
        )
        return 0
    except Exception as exc:
        log_lineage_event(
            data_dir=curated_dir.parent,
            job_name="load_duckdb_tables",
            layer="analytics",
            code_path=Path(__file__),
            transform_summary="Load curated parquet datasets into DuckDB analytics tables.",
            input_paths=input_paths,
            output_paths=output_paths,
            status="failed",
            error_message=str(exc),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
