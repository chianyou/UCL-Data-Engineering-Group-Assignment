#!/usr/bin/env python3
"""Read raw data from MongoDB with PySpark and write curated Parquet outputs."""

from __future__ import annotations

import argparse
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "curated" / "spark_pipeline"
DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_DATABASE = "cyber_risk_raw"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build curated vulnerability dataset from MongoDB raw collections via PySpark."
    )
    parser.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI, help="MongoDB URI.")
    parser.add_argument("--database", default=DEFAULT_DATABASE, help="MongoDB database name.")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Output directory for curated parquet datasets.",
    )
    parser.add_argument("--spark-master", default="", help="Optional Spark master URL.")
    return parser.parse_args()


def build_spark_session(args: argparse.Namespace) -> SparkSession:
    builder = SparkSession.builder.appName("MongoToParquetPipeline")
    if args.spark_master:
        builder = builder.master(args.spark_master)

    return (
        builder.config("spark.sql.session.timeZone", "UTC")
        .config("spark.mongodb.read.connection.uri", args.mongo_uri)
        .config("spark.mongodb.write.connection.uri", args.mongo_uri)
        .getOrCreate()
    )


def read_collection(spark: SparkSession, database: str, collection: str) -> DataFrame:
    return (
        spark.read.format("mongodb")
        .option("database", database)
        .option("collection", collection)
        .load()
    )


def latest_snapshot(df: DataFrame) -> DataFrame:
    latest_date = df.select(F.max("snapshot_date").alias("max_date")).collect()[0]["max_date"]
    if latest_date is None:
        return df.limit(0)
    return df.where(F.col("snapshot_date") == latest_date)


def build_nvd_df(nvd_docs: DataFrame) -> DataFrame:
    exploded = nvd_docs.select(F.explode("payload.vulnerabilities").alias("vuln"))

    cwe_expr = F.expr(
        "filter(transform(flatten(transform(vuln.cve.weaknesses, w -> w.description)), x -> x.value), x -> x like 'CWE-%')[0]"
    )
    criteria_expr = F.expr(
        "vuln.cve.configurations[0].nodes[0].cpeMatch[0].criteria"
    )

    return (
        exploded.select(
            F.col("vuln.cve.id").alias("cve_id"),
            F.col("vuln.cve.published").alias("published"),
            F.col("vuln.cve.lastModified").alias("last_modified"),
            F.col("vuln.cve.vulnStatus").alias("vuln_status"),
            F.coalesce(
                F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["version"],
                F.col("vuln.cve.metrics.cvssMetricV30")[0]["cvssData"]["version"],
                F.col("vuln.cve.metrics.cvssMetricV2")[0]["cvssData"]["version"],
            ).alias("cvss_version"),
            F.coalesce(
                F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseScore"],
                F.col("vuln.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseScore"],
                F.col("vuln.cve.metrics.cvssMetricV2")[0]["cvssData"]["baseScore"],
            ).cast("double").alias("cvss_base_score"),
            F.coalesce(
                F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseSeverity"],
                F.col("vuln.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseSeverity"],
                F.col("vuln.cve.metrics.cvssMetricV2")[0]["baseSeverity"],
            ).alias("cvss_severity"),
            cwe_expr.alias("cwe_id"),
            F.regexp_extract(criteria_expr, r"^cpe:2\.3:[aho]:([^:]+):", 1).alias("vendor"),
            F.regexp_extract(criteria_expr, r"^cpe:2\.3:[aho]:[^:]+:([^:]+):", 1).alias("product"),
        )
        .where(F.col("cve_id").isNotNull())
        .dropDuplicates(["cve_id"])
    )


def build_kev_df(kev_docs: DataFrame) -> DataFrame:
    return (
        kev_docs.select(F.explode("payload.vulnerabilities").alias("kev"))
        .select(
            F.col("kev.cveID").alias("cve_id"),
            F.col("kev.dateAdded").alias("kev_date_added"),
            F.col("kev.dueDate").alias("kev_due_date"),
            F.col("kev.knownRansomwareCampaignUse").alias("kev_ransomware_use"),
        )
        .where(F.col("cve_id").isNotNull())
        .dropDuplicates(["cve_id"])
    )


def build_epss_df(epss_docs: DataFrame, epss_chunks: DataFrame) -> DataFrame:
    latest_meta = (
        epss_docs.where(F.col("source_name") == "epss")
        .orderBy(F.col("ingested_at").desc())
        .select("file_name", F.col("payload._chunked").alias("is_chunked"), "payload.data")
        .limit(1)
    )
    meta = latest_meta.collect()
    if not meta:
        return epss_docs.sparkSession.createDataFrame([], "cve_id string, epss_score double, epss_percentile double")

    latest_file = meta[0]["file_name"]
    is_chunked = bool(meta[0]["is_chunked"])

    if is_chunked:
        return (
            epss_chunks.where((F.col("source_name") == "epss") & (F.col("file_name") == latest_file))
            .select(F.explode("payload_chunk").alias("epss"))
            .select(
                F.col("epss.cve").alias("cve_id"),
                F.col("epss.epss").cast("double").alias("epss_score"),
                F.col("epss.percentile").cast("double").alias("epss_percentile"),
            )
            .where(F.col("cve_id").isNotNull())
            .dropDuplicates(["cve_id"])
        )

    return (
        latest_meta.select(F.explode("data").alias("epss"))
        .select(
            F.col("epss.cve").alias("cve_id"),
            F.col("epss.epss").cast("double").alias("epss_score"),
            F.col("epss.percentile").cast("double").alias("epss_percentile"),
        )
        .where(F.col("cve_id").isNotNull())
        .dropDuplicates(["cve_id"])
    )


def with_priority_bucket(df: DataFrame) -> DataFrame:
    return df.withColumn(
        "priority_bucket",
        F.when(F.col("in_kev"), F.lit("critical"))
        .when(F.col("epss_score") >= F.lit(0.9), F.lit("critical"))
        .when(F.col("cvss_base_score") >= F.lit(9.0), F.lit("critical"))
        .when(F.col("epss_score") >= F.lit(0.7), F.lit("high"))
        .when(F.col("cvss_base_score") >= F.lit(7.0), F.lit("high"))
        .when(F.col("epss_score") >= F.lit(0.3), F.lit("medium"))
        .when(F.col("cvss_base_score") >= F.lit(4.0), F.lit("medium"))
        .otherwise(F.lit("low")),
    )


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    spark = build_spark_session(args)
    try:
        nvd_docs = latest_snapshot(read_collection(spark, args.database, "raw_nvd_feeds"))
        kev_docs = latest_snapshot(read_collection(spark, args.database, "raw_cisa_kev_feeds"))
        epss_docs = latest_snapshot(read_collection(spark, args.database, "raw_epss_feeds"))
        epss_chunks = read_collection(spark, args.database, "raw_epss_feeds_chunks")

        nvd_df = build_nvd_df(nvd_docs)
        kev_df = build_kev_df(kev_docs)
        epss_df = build_epss_df(epss_docs, epss_chunks)

        curated_df = (
            nvd_df.join(kev_df, on="cve_id", how="left")
            .join(epss_df, on="cve_id", how="left")
            .withColumn("in_kev", F.col("kev_date_added").isNotNull())
        )
        curated_df = with_priority_bucket(curated_df)

        output_path = output_dir / "vulnerability_priority_from_mongodb.parquet"
        curated_df.repartition(1).write.mode("overwrite").parquet(str(output_path))

        print(f"Curated rows from MongoDB via PySpark: {curated_df.count()}")
        print(f"Output parquet: {output_path.resolve()}")
    finally:
        spark.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
