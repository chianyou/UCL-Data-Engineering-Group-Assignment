"""Simple Airflow DAG for the cyber risk pipeline.

Pipeline order:
1) Ingestion (NVD, CISA KEV, EPSS, cvelistV5)
2) Load raw snapshots into MongoDB
3) Build curated outputs (mart, bridges, star schema, summaries)
4) Load curated parquet into DuckDB
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.python import PythonOperator


def repo_root() -> Path:
    configured = os.getenv("AIRFLOW_REPO_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def python_bin() -> str:
    return os.getenv("AIRFLOW_PYTHON_BIN", "python3").strip() or "python3"


def maybe_ca_bundle() -> list[str]:
    ca_bundle = os.getenv("AIRFLOW_CA_BUNDLE", "").strip()
    if not ca_bundle:
        return []
    return ["--ca-bundle", ca_bundle]


def run_script(script_rel_path: str, args: list[str] | None = None) -> None:
    root = repo_root()
    script_path = root / script_rel_path
    command = [python_bin(), str(script_path)]
    if args:
        command.extend(args)

    env = os.environ.copy()
    subprocess.run(command, cwd=root, check=True, env=env)


default_args = {
    "owner": "data-engineering-team",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}


with DAG(
    dag_id="cyber_risk_daily_pipeline",
    description="Ingest, transform, and load cyber risk datasets into DuckDB.",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="@daily",
    catchup=False,
    tags=["cyber-risk", "etl", "duckdb", "mongodb"],
) as dag:
    ingest_nvd = PythonOperator(
        task_id="ingest_nvd",
        python_callable=run_script,
        op_kwargs={
            "script_rel_path": "src/ingestion/nvd/ingest_nvd.py",
            "args": ["--days", "30", *maybe_ca_bundle()],
        },
    )

    ingest_cisa_kev = PythonOperator(
        task_id="ingest_cisa_kev",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/ingestion/cisa_kev/fetch_cisa_kev.py"},
    )

    ingest_epss = PythonOperator(
        task_id="ingest_epss",
        python_callable=run_script,
        op_kwargs={
            "script_rel_path": "src/ingestion/epss/fetch_epss.py",
            "args": maybe_ca_bundle(),
        },
    )

    ingest_cvelist = PythonOperator(
        task_id="ingest_cvelist_v5",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/ingestion/cvelist/fetch_cvelist_v5.py"},
    )

    load_mongodb_raw = PythonOperator(
        task_id="load_raw_snapshots_to_mongodb",
        python_callable=run_script,
        op_kwargs={
            "script_rel_path": "src/storage/mongodb/load_raw_snapshots.py",
            "args": [
                "--mongo-uri",
                os.getenv(
                    "AIRFLOW_MONGO_URI",
                    "mongodb://admin:admin123@localhost:27017/?authSource=admin",
                ),
                "--database",
                os.getenv("AIRFLOW_MONGO_DATABASE", "cyber_risk_raw"),
            ],
        },
    )

    build_mart = PythonOperator(
        task_id="build_vulnerability_mart",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/transformation/build_vulnerability_mart.py"},
    )

    build_product_bridge = PythonOperator(
        task_id="build_cve_product_bridge",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/transformation/build_cve_product_bridge.py"},
    )

    build_cvelist_enrichment = PythonOperator(
        task_id="build_cvelist_enrichment",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/transformation/build_cvelist_enrichment.py"},
    )

    build_star_schema = PythonOperator(
        task_id="build_star_schema",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/transformation/build_star_schema.py"},
    )

    build_summaries = PythonOperator(
        task_id="build_transformation_summaries",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/transformation/build_transformation_summaries.py"},
    )

    load_duckdb = PythonOperator(
        task_id="load_duckdb_tables",
        python_callable=run_script,
        op_kwargs={"script_rel_path": "src/analytics/duckdb/load_duckdb.py"},
    )

    [ingest_nvd, ingest_cisa_kev, ingest_epss, ingest_cvelist] >> load_mongodb_raw
    load_mongodb_raw >> build_mart
    build_mart >> build_product_bridge >> build_star_schema
    build_mart >> build_cvelist_enrichment
    [build_star_schema, build_cvelist_enrichment] >> build_summaries >> load_duckdb
