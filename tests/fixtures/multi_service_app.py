"""Multi-service GCP application — used by test_scanner_real.py.

Combines BigQuery, Cloud Storage, and Secret Manager in one file.
"""

from google.cloud import bigquery, secretmanager, storage

bq = bigquery.Client()
gcs = storage.Client()
sm = secretmanager.SecretManagerServiceClient()

# Read a secret
response = sm.access_secret_version(
    request={"name": "projects/my-proj/secrets/db-password/versions/latest"}
)
password = response.payload.data.decode("utf-8")

# Query BigQuery with the secret
job = bq.query(f"SELECT * FROM analytics.users WHERE token = '{password}'")
rows = job.result()

# Export results to GCS
bucket = gcs.get_bucket("my-exports")
blob = bucket.blob("exports/users.csv")
blob.upload_from_filename("/tmp/users.csv")
