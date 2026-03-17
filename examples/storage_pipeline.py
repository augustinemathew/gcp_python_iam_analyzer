"""Cloud Storage pipeline: upload, download, copy, and delete objects."""

from google.cloud import storage


def upload_file(bucket_name: str, source_path: str, destination_blob: str):
    client = storage.Client()
    bucket = client.get_bucket(bucket_name)
    blob = bucket.blob(destination_blob)
    blob.upload_from_filename(source_path)
    print(f"Uploaded {source_path} to gs://{bucket_name}/{destination_blob}")


def download_file(bucket_name: str, source_blob: str, destination_path: str):
    client = storage.Client()
    bucket = client.get_bucket(bucket_name)
    blob = bucket.blob(source_blob)
    blob.download_to_filename(destination_path)
    print(f"Downloaded gs://{bucket_name}/{source_blob} to {destination_path}")


def copy_object(
    src_bucket: str, src_blob: str, dst_bucket: str, dst_blob: str
):
    client = storage.Client()
    source_bucket = client.get_bucket(src_bucket)
    source = source_bucket.blob(src_blob)
    destination_bucket = client.get_bucket(dst_bucket)
    source_bucket.copy_blob(source, destination_bucket, dst_blob)
    print(f"Copied gs://{src_bucket}/{src_blob} to gs://{dst_bucket}/{dst_blob}")


def list_and_delete(bucket_name: str, prefix: str):
    client = storage.Client()
    blobs = client.list_blobs(bucket_name, prefix=prefix)
    for blob in blobs:
        blob.delete()
        print(f"Deleted gs://{bucket_name}/{blob.name}")
