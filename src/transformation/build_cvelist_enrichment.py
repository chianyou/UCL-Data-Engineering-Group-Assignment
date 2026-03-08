#!/usr/bin/env python3
"""Build curated enrichment tables from the official cvelistV5 snapshot."""

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
        description="Extract curated CVE record enrichment tables from cvelistV5."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Base data directory (default: <repo>/data).",
    )
    return parser.parse_args()


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


def find_snapshot_root(base_dir: Path) -> Path:
    snapshot_dir = base_dir / "raw" / "cvelistv5" / "snapshot"
    if not snapshot_dir.exists():
        raise FileNotFoundError("cvelistV5 snapshot directory not found. Run the ingestion step first.")

    roots = [path for path in snapshot_dir.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("Expected exactly one extracted cvelistV5 root directory.")
    return roots[0]


def iter_cve_json_files(snapshot_root: Path) -> list[Path]:
    cves_dir = snapshot_root / "cves"
    return sorted(cves_dir.rglob("*.json"))


def get_english_descriptions(container: dict[str, Any]) -> str:
    descriptions = []
    for item in container.get("descriptions", []):
        if item.get("lang") == "en" and item.get("value"):
            descriptions.append(item["value"].strip())
    return " | ".join(descriptions)


def extract_problem_types(container: dict[str, Any], cve_id: str, container_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for problem_type_index, problem_type in enumerate(container.get("problemTypes", []), start=1):
        for description_index, description in enumerate(problem_type.get("descriptions", []), start=1):
            rows.append(
                {
                    "cve_id": cve_id,
                    "container_name": container_name,
                    "problem_type_index": problem_type_index,
                    "description_index": description_index,
                    "lang": description.get("lang", ""),
                    "type": description.get("type", ""),
                    "cwe_id": description.get("cweId", ""),
                    "description": description.get("description", ""),
                }
            )
    return rows


def extract_references(container: dict[str, Any], cve_id: str, container_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for reference_index, reference in enumerate(container.get("references", []), start=1):
        rows.append(
            {
                "cve_id": cve_id,
                "container_name": container_name,
                "reference_index": reference_index,
                "url": reference.get("url", ""),
                "name": reference.get("name", ""),
                "tags": ",".join(reference.get("tags", [])),
            }
        )
    return rows


def extract_container_rows(containers: dict[str, Any], cve_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        rows.append(
            {
                "cve_id": cve_id,
                "container_name": "cna",
                "provider_metadata_org_id": cna.get("providerMetadata", {}).get("orgId", ""),
                "title": cna.get("title", ""),
                "descriptions_en": get_english_descriptions(cna),
                "date_public": cna.get("datePublic", ""),
            }
        )

    for adp_index, adp in enumerate(containers.get("adp", []), start=1):
        rows.append(
            {
                "cve_id": cve_id,
                "container_name": f"adp_{adp_index}",
                "provider_metadata_org_id": adp.get("providerMetadata", {}).get("orgId", ""),
                "title": adp.get("title", ""),
                "descriptions_en": get_english_descriptions(adp),
                "date_public": adp.get("datePublic", ""),
            }
        )
    return rows


def build_rows(
    files: list[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    summary_rows: list[dict[str, Any]] = []
    reference_rows: list[dict[str, Any]] = []
    problem_type_rows: list[dict[str, Any]] = []
    container_rows: list[dict[str, Any]] = []
    skipped_files = 0

    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            skipped_files += 1
            continue
        cve_metadata = payload.get("cveMetadata", {})
        if not isinstance(cve_metadata, dict) or not cve_metadata.get("cveId"):
            skipped_files += 1
            continue
        containers = payload.get("containers", {})
        cve_id = cve_metadata.get("cveId", "")
        cna = containers.get("cna", {})

        summary_rows.append(
            {
                "cve_id": cve_id,
                "state": cve_metadata.get("state", ""),
                "date_reserved": cve_metadata.get("dateReserved", ""),
                "date_published": cve_metadata.get("datePublished", ""),
                "date_updated": cve_metadata.get("dateUpdated", ""),
                "assigner_org_id": cve_metadata.get("assignerOrgId", ""),
                "assigner_short_name": cve_metadata.get("assignerShortName", ""),
                "title": cna.get("title", ""),
                "descriptions_en": get_english_descriptions(cna),
                "data_type": payload.get("dataType", ""),
                "data_version": payload.get("dataVersion", ""),
            }
        )

        container_rows.extend(extract_container_rows(containers, cve_id))
        if isinstance(cna, dict):
            reference_rows.extend(extract_references(cna, cve_id, "cna"))
            problem_type_rows.extend(extract_problem_types(cna, cve_id, "cna"))

        for adp_index, adp in enumerate(containers.get("adp", []), start=1):
            container_name = f"adp_{adp_index}"
            reference_rows.extend(extract_references(adp, cve_id, container_name))
            problem_type_rows.extend(extract_problem_types(adp, cve_id, container_name))

    return summary_rows, reference_rows, problem_type_rows, container_rows, skipped_files


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    snapshot_root = find_snapshot_root(data_dir)
    files = iter_cve_json_files(snapshot_root)
    if not files:
        raise FileNotFoundError("No CVE JSON files found under the cvelistV5 snapshot.")

    curated_dir = data_dir / "curated" / "cve_records"
    curated_dir.mkdir(parents=True, exist_ok=True)

    output_paths = [
        curated_dir / "dim_cve_records_latest.csv",
        curated_dir / "bridge_cve_references_latest.csv",
        curated_dir / "bridge_cve_problem_types_latest.csv",
        curated_dir / "fact_cve_containers_latest.csv",
        curated_dir / "dim_cve_records_latest.parquet",
        curated_dir / "bridge_cve_references_latest.parquet",
        curated_dir / "bridge_cve_problem_types_latest.parquet",
        curated_dir / "fact_cve_containers_latest.parquet",
    ]

    try:
        summary_rows, reference_rows, problem_type_rows, container_rows, skipped_files = build_rows(files)

        write_csv(curated_dir / "dim_cve_records_latest.csv", summary_rows)
        write_csv(curated_dir / "bridge_cve_references_latest.csv", reference_rows)
        write_csv(curated_dir / "bridge_cve_problem_types_latest.csv", problem_type_rows)
        write_csv(curated_dir / "fact_cve_containers_latest.csv", container_rows)

        summary_parquet = write_parquet_if_available(
            curated_dir / "dim_cve_records_latest.parquet", summary_rows
        )
        references_parquet = write_parquet_if_available(
            curated_dir / "bridge_cve_references_latest.parquet", reference_rows
        )
        problem_types_parquet = write_parquet_if_available(
            curated_dir / "bridge_cve_problem_types_latest.parquet", problem_type_rows
        )
        containers_parquet = write_parquet_if_available(
            curated_dir / "fact_cve_containers_latest.parquet", container_rows
        )

        print(f"Built CVE record summary rows: {len(summary_rows)}")
        print(f"Built CVE reference rows: {len(reference_rows)}")
        print(f"Built CVE problem type rows: {len(problem_type_rows)}")
        print(f"Built CVE container rows: {len(container_rows)}")
        print(f"Skipped non-CVE JSON files: {skipped_files}")
        if summary_parquet and references_parquet and problem_types_parquet and containers_parquet:
            print("Parquet outputs created for all cvelistV5 enrichment tables")
        else:
            print("Parquet skipped for some or all cvelistV5 enrichment tables: pyarrow not installed")

        log_lineage_event(
            data_dir=data_dir,
            job_name="build_cvelist_enrichment",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Extract dim/bridge enrichment tables from cvelistV5 containers.",
            input_paths=files,
            output_paths=output_paths,
            status="success",
            input_count=len(files),
            output_count=len(summary_rows),
        )
        return 0
    except Exception as exc:
        log_lineage_event(
            data_dir=data_dir,
            job_name="build_cvelist_enrichment",
            layer="curated",
            code_path=Path(__file__),
            transform_summary="Extract dim/bridge enrichment tables from cvelistV5 containers.",
            input_paths=files,
            output_paths=output_paths,
            status="failed",
            error_message=str(exc),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
