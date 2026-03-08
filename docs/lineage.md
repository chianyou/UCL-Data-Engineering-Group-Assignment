# Data Lineage

This project tracks lineage at job level for key transformation and analytics scripts.

## Lineage Output Location

- `data/curated/lineage/lineage_events_latest.csv`
- `data/curated/lineage/lineage_events_latest.jsonl`

## Tracked Fields

- `run_id`: unique ID per execution event
- `run_ts_utc`: run timestamp (UTC)
- `job_name`: pipeline job name
- `layer`: data layer (`curated` or `analytics`)
- `status`: `success` or `failed`
- `code_path`: script path
- `transform_summary`: short transformation description
- `input_count`: input row/object count (when available)
- `output_count`: output row/object count (when available)
- `error_message`: failure reason if any
- `input_datasets`: JSON metadata list (path, exists, size, modified time)
- `output_datasets`: JSON metadata list (path, exists, size, modified time)

## Jobs Currently Logging Lineage

- `build_vulnerability_mart`
- `build_cve_product_bridge`
- `build_cvelist_enrichment`
- `build_star_schema`
- `build_transformation_summaries`
- `load_duckdb_tables`

## Why This Helps

- Tracks origin files and output artifacts for each pipeline step.
- Provides evidence for transformation logic and run outcomes.
- Supports auditability and reproducibility in reports/demo.

## Quick Query Example (DuckDB)

```sql
SELECT
  run_ts_utc,
  job_name,
  layer,
  status,
  input_count,
  output_count,
  error_message
FROM read_csv_auto('data/curated/lineage/lineage_events_latest.csv')
ORDER BY run_ts_utc DESC
LIMIT 20;
```
