# MongoDB to PySpark Pipeline

This document describes the pipeline variant that follows:

`MongoDB raw -> PySpark read -> curated Parquet`

## Scope

This is an additional pipeline path for assignment alignment.  
It does not replace the existing Python ETL scripts.

## Input Collections

- `raw_nvd_feeds`
- `raw_cisa_kev_feeds`
- `raw_epss_feeds`
- `raw_epss_feeds_chunks` (used when EPSS payload is chunked)

## Output

- `data/curated/spark_pipeline/vulnerability_priority_from_mongodb.parquet`

## Script

- [mongo_to_parquet_pyspark.py](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/src/transformation/spark/mongo_to_parquet_pyspark.py)

## Example Command

```bash
spark-submit \
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 \
  src/transformation/spark/mongo_to_parquet_pyspark.py \
  --mongo-uri mongodb://localhost:27017 \
  --database cyber_risk_raw
```

If your Spark environment uses a different Scala version, adjust the connector package suffix accordingly.
