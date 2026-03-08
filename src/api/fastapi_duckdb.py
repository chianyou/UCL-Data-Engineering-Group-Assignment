#!/usr/bin/env python3
"""FastAPI service exposing DuckDB-backed analytics endpoints."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import duckdb
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DUCKDB_PATH = REPO_ROOT / "data" / "analytics.duckdb"


def get_db_path() -> Path:
    configured = os.getenv("DUCKDB_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return DEFAULT_DUCKDB_PATH


def query_rows(sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
    db_path = get_db_path()
    if not db_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"DuckDB file not found: {db_path}",
        )

    with duckdb.connect(str(db_path), read_only=True) as con:
        result = con.execute(sql, params or [])
        columns = [desc[0] for desc in result.description]
        rows = result.fetchall()

    return [dict(zip(columns, row)) for row in rows]


def parse_origins() -> list[str]:
    raw = os.getenv("ALLOWED_ORIGINS", "*").strip()
    if raw == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def autoload_duckdb_enabled() -> bool:
    return os.getenv("AUTOLOAD_DUCKDB", "1").strip().lower() not in {"0", "false", "no"}


def ensure_duckdb_ready() -> None:
    db_path = get_db_path()
    if db_path.exists():
        return
    if not autoload_duckdb_enabled():
        return

    loader_script = REPO_ROOT / "src" / "analytics" / "duckdb" / "load_duckdb.py"
    cmd = [sys.executable, str(loader_script), "--db-path", str(db_path)]
    curated_dir = os.getenv("CURATED_DIR", "").strip()
    if curated_dir:
        cmd.extend(["--curated-dir", curated_dir])

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise RuntimeError(f"Failed to initialize DuckDB at startup: {detail}") from exc


app = FastAPI(
    title="Cyber Risk Analytics API",
    version="1.0.0",
    description="Serve dashboard-ready datasets from DuckDB.",
)

origins = parse_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_init() -> None:
    ensure_duckdb_ready()


@app.get("/health")
def health() -> dict[str, Any]:
    db_path = get_db_path()
    return {
        "status": "ok",
        "duckdb_path": str(db_path),
        "duckdb_exists": db_path.exists(),
    }


@app.get("/api/agg/daily-new-cves")
def daily_new_cves(limit: int = Query(default=365, ge=1, le=5000)) -> list[dict[str, Any]]:
    return query_rows(
        """
        SELECT published_date, new_cve_count
        FROM agg_daily_new_cves
        ORDER BY published_date ASC
        LIMIT ?
        """,
        [limit],
    )


@app.get("/api/agg/cvss-severity-distribution")
def cvss_severity_distribution() -> list[dict[str, Any]]:
    return query_rows(
        """
        SELECT cvss_severity, cve_count
        FROM agg_cvss_severity_distribution
        ORDER BY cve_count DESC
        """
    )


@app.get("/api/agg/kev-hit-rate")
def kev_hit_rate() -> list[dict[str, Any]]:
    return query_rows(
        """
        SELECT cvss_severity, total_cves, kev_cves, kev_hit_rate
        FROM agg_kev_hit_rate_by_cvss_severity
        ORDER BY total_cves DESC
        """
    )


@app.get("/api/agg/epss-vendor-product")
def epss_vendor_product(limit: int = Query(default=500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return query_rows(
        """
        SELECT vendor, product, total_cves, scored_cves, high_epss_cves, high_epss_rate, avg_epss_score
        FROM agg_epss_by_vendor_product
        ORDER BY avg_epss_score DESC, scored_cves DESC
        LIMIT ?
        """,
        [limit],
    )


@app.get("/api/agg/cwe-vendor-product")
def cwe_vendor_product(limit: int = Query(default=500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return query_rows(
        """
        SELECT cwe_id, vendor, product, cve_count, kev_cves, kev_hit_rate, avg_epss_score
        FROM agg_cwe_vendor_product
        ORDER BY cve_count DESC
        LIMIT ?
        """,
        [limit],
    )
