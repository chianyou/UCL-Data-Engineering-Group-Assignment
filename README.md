# UCL Data Engineering Group Assignment

This repository implements a cyber-risk data engineering pipeline using NVD, CISA KEV, EPSS, and cvelistV5.

## End-to-End Flow

`Data Sources -> Raw Files -> MongoDB (raw) -> PySpark/Python Transform -> Curated Parquet -> DuckDB -> FastAPI -> Dashboard`

- Ingestion scripts land source files in `data/raw`.
- MongoDB stores raw snapshots for replayable processing.
- Transformation builds curated/star/aggregation datasets.
- DuckDB serves analytics tables from curated Parquet.
- FastAPI exposes dashboard-ready endpoints.
- Dashboard renders metrics/charts from API (or CSV fallback).

## Project Structure

```text
.
|-- airflow
|-- data
|   |-- raw
|   |-- staging
|   `-- curated
|-- dashboard
|-- docs
|-- notebooks
|-- sql
|   |-- duckdb
|   `-- postgres
`-- src
    |-- analytics
    |-- api
    |-- ingestion
    |-- storage
    `-- transformation
```

## Key Scripts

- Ingestion
  - `src/ingestion/nvd/ingest_nvd.py`
  - `src/ingestion/cisa_kev/fetch_cisa_kev.py`
  - `src/ingestion/epss/fetch_epss.py`
  - `src/ingestion/cvelist/fetch_cvelist_v5.py`
- Raw storage
  - `src/storage/mongodb/load_raw_snapshots.py`
- Transformation
  - PySpark: `src/transformation/spark/mongo_to_parquet_pyspark.py`
  - Python curated/star/aggregations:
    - `src/transformation/build_vulnerability_mart.py`
    - `src/transformation/build_cve_product_bridge.py`
    - `src/transformation/build_cvelist_enrichment.py`
    - `src/transformation/build_star_schema.py`
    - `src/transformation/build_transformation_summaries.py`
- Analytics/API
  - DuckDB loader: `src/analytics/duckdb/load_duckdb.py`
  - FastAPI service: `src/api/fastapi_duckdb.py`
- Orchestration
  - Airflow DAG: `airflow/dags/cyber_risk_pipeline.py`

## Run Pipeline

1. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

2. Ingest source data

```bash
python3 src/ingestion/nvd/ingest_nvd.py --days 30
python3 src/ingestion/cisa_kev/fetch_cisa_kev.py
python3 src/ingestion/epss/fetch_epss.py
python3 src/ingestion/cvelist/fetch_cvelist_v5.py
```

3. Start MongoDB and load raw snapshots

```bash
docker compose up -d mongodb
python3 src/storage/mongodb/load_raw_snapshots.py
```

Default MongoDB settings:
- URI: `mongodb://admin:admin123@localhost:27017/?authSource=admin`
- database: `cyber_risk_raw`

4. Run transformation

PySpark path (MongoDB raw -> Parquet):

```bash
spark-submit \
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 \
  src/transformation/spark/mongo_to_parquet_pyspark.py \
  --mongo-uri mongodb://localhost:27017 \
  --database cyber_risk_raw
```

Python curated/star/summary path:

```bash
python3 src/transformation/build_vulnerability_mart.py
python3 src/transformation/build_cve_product_bridge.py
python3 src/transformation/build_cvelist_enrichment.py
python3 src/transformation/build_star_schema.py
python3 src/transformation/build_transformation_summaries.py
```

5. Load DuckDB analytics tables

```bash
python3 src/analytics/duckdb/load_duckdb.py
```

Run DuckDB analytics query pack (`sql/duckdb/queries.sql`, 14 queries):

```bash
python3 - <<'PY'
import duckdb
from pathlib import Path

con = duckdb.connect("data/analytics.duckdb")
sql = Path("sql/duckdb/queries.sql").read_text(encoding="utf-8")
for i, stmt in enumerate([s.strip() for s in sql.split(";") if s.strip()], 1):
    print(f"\n--- Query {i} ---")
    print(con.execute(stmt).fetchdf().head(20).to_string(index=False))
con.close()
PY
```

6. Start API and dashboard

```bash
python3 -m uvicorn src.api.fastapi_duckdb:app --host 0.0.0.0 --port 8001 --reload
```

```bash
python3 -m http.server 8000
```

Open:
- Dashboard (CSV mode): `http://127.0.0.1:8000/dashboard/`
- Dashboard (API mode): `http://127.0.0.1:8000/dashboard/?api_base=http://127.0.0.1:8001`
- API health: `http://127.0.0.1:8001/health`
- API docs: `http://127.0.0.1:8001/docs`

## Deploy API on Render

This repo includes `render.yaml` for Blueprint deployment.

1. Push current branch to GitHub.
2. In Render, create a new Blueprint and select this repository.
3. Deploy the `cyber-risk-api` web service.
4. After deploy, open:
   - `https://<your-render-domain>/health`
   - `https://<your-render-domain>/docs`
5. Point dashboard API mode to Render:
   - `...?api_base=https://<your-render-domain>`

Recommended Render environment variables:
- `ALLOWED_ORIGINS=https://<your-github-pages-domain>`
- `AUTOLOAD_DUCKDB=1`

Notes:
- On free plans, filesystem persistence is limited; DuckDB may be rebuilt on restart.
- Startup auto-load uses `src/analytics/duckdb/load_duckdb.py` when DB file is missing.
- On Render free instances, the API may spin down after ~15 minutes of inactivity.
- First request after inactivity may take up to ~60 seconds (cold start).
- For demos, pre-warm the API by opening `/health` before loading the dashboard.

## Deployment Architecture (Current)

The project is deployed as:

- Frontend dashboard on GitHub Pages
- Backend API (FastAPI + DuckDB) on Render

The frontend calls the Render API via the `api_base` query parameter.

Example production URL pattern:

- `https://<github-user>.github.io/<repo-name>/dashboard/?api_base=https://<render-service>.onrender.com`

Current setup example:

- `https://chianyou.github.io/UCL-Data-Engineering-Group-Assignment/dashboard/?api_base=https://cyber-risk-api.onrender.com`

## Data Lineage

Job-level lineage tracking is enabled for key transformation and analytics scripts.

Lineage outputs:
- `data/curated/lineage/lineage_events_latest.csv`
- `data/curated/lineage/lineage_events_latest.jsonl`
- `data/curated/lineage/lineage_events_sample.csv` (lightweight sample for repository sharing)
- `data/curated/lineage/lineage_events_sample.jsonl` (lightweight sample for repository sharing)

Tracked jobs:
- `build_vulnerability_mart`
- `build_cve_product_bridge`
- `build_cvelist_enrichment`
- `build_star_schema`
- `build_transformation_summaries`
- `load_duckdb_tables`

Detailed field definitions and query examples:
- `docs/lineage.md`

Repository note:
- Full lineage logs can become very large due to embedded dataset metadata.
- GitHub file size limit is 100 MB per file, so this repository shares sample lineage files and keeps full logs local.

## Notes

- If `duckdb` CLI is unavailable, use Python scripts for loading/querying.
- If DuckDB lock conflicts appear, close the process holding `data/analytics.duckdb`.
- In JupyterHub, use proxy URLs instead of localhost ports.
- Airflow orchestration example is provided under `airflow/`.
