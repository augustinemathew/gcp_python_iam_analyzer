"""Acme Data Pipeline — Cloud Run job (cron-triggered).

Runs on a schedule, no user interaction. Uses the attached SA for everything.
Reads from BigQuery, writes processed results to Cloud Storage,
encrypts sensitive output with KMS.

Single identity context: App SA only.
"""

from __future__ import annotations

import json
import os

from google.cloud import bigquery, kms, storage

PROJECT_ID = os.environ.get("PROJECT_ID", "acme-prod")
KMS_KEY = os.environ.get("KMS_KEY", "projects/acme-prod/locations/global/keyRings/pipeline/cryptoKeys/output-key")
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "acme-pipeline-output")


def extract() -> list[dict]:
    """Read raw data from BigQuery."""
    client = bigquery.Client(project=PROJECT_ID)
    query = """
        SELECT user_id, event_type, timestamp, metadata
        FROM `acme-prod.analytics.events`
        WHERE DATE(timestamp) = CURRENT_DATE()
    """
    rows = client.query(query).result()
    return [dict(row) for row in rows]


def transform(records: list[dict]) -> list[dict]:
    """Process records — aggregate by user."""
    by_user: dict[str, list] = {}
    for r in records:
        by_user.setdefault(r["user_id"], []).append(r)
    return [
        {"user_id": uid, "event_count": len(events), "events": events}
        for uid, events in by_user.items()
    ]


def encrypt_payload(payload: bytes) -> bytes:
    """Encrypt output using Cloud KMS."""
    client = kms.KeyManagementServiceClient()
    response = client.encrypt(
        request={"name": KMS_KEY, "plaintext": payload}
    )
    return response.ciphertext


def load(results: list[dict]) -> str:
    """Write encrypted results to Cloud Storage."""
    payload = json.dumps(results, default=str).encode()
    encrypted = encrypt_payload(payload)

    gcs = storage.Client(project=PROJECT_ID)
    bucket = gcs.bucket(OUTPUT_BUCKET)
    blob = bucket.blob(f"output/{os.environ.get('CLOUD_RUN_EXECUTION', 'local')}.enc")
    blob.upload_from_string(encrypted, content_type="application/octet-stream")
    return f"gs://{OUTPUT_BUCKET}/{blob.name}"


def main() -> None:
    """ETL pipeline: extract → transform → encrypt → load."""
    records = extract()
    results = transform(records)
    output_path = load(results)
    print(f"Pipeline complete: {len(results)} users, output: {output_path}")


if __name__ == "__main__":
    main()
