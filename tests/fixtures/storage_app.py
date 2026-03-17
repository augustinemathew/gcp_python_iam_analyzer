"""Sample Cloud Storage application — used by test_scanner_real.py."""

from google.cloud import storage

client = storage.Client()

# Get a bucket
bucket = client.get_bucket("my-data-bucket")

# List blobs
blobs = client.list_blobs("my-data-bucket", prefix="uploads/")

# Upload a file
blob = bucket.blob("uploads/report.csv")
blob.upload_from_filename("/tmp/report.csv")

# Download a file
blob.download_to_filename("/tmp/local_report.csv")
