# Airflow (Simple Orchestration)

This folder contains a minimal DAG to orchestrate the project pipeline.

## DAG

- `airflow/dags/cyber_risk_pipeline.py`
- DAG ID: `cyber_risk_daily_pipeline`
- Schedule: `@daily`

## What the DAG runs

1. Ingestion: NVD, CISA KEV, EPSS, cvelistV5
2. Raw load: JSON snapshots to MongoDB
3. Transformation: mart, bridge, enrichment, star schema, summaries
4. Analytics load: curated parquet into DuckDB

## Environment variables (optional)

- `AIRFLOW_REPO_ROOT` (default auto-detected from DAG path)
- `AIRFLOW_PYTHON_BIN` (default `python3`)
- `AIRFLOW_CA_BUNDLE` (for TLS certificate issues)
- `AIRFLOW_MONGO_URI` (default `mongodb://admin:admin123@localhost:27017/?authSource=admin`)
- `AIRFLOW_MONGO_DATABASE` (default `cyber_risk_raw`)

## Quick local run (standalone Airflow)

1. Install Airflow in your runtime (or use your existing Airflow environment).
2. Point Airflow to this DAG:
   - set `AIRFLOW_HOME`
   - place/symlink `airflow/dags/cyber_risk_pipeline.py` into `$AIRFLOW_HOME/dags`
3. Start Airflow and trigger `cyber_risk_daily_pipeline`.

## Notes

- This DAG intentionally uses existing project scripts for simplicity.
- For production, split tasks into containers and pin runtime images/dependencies.
