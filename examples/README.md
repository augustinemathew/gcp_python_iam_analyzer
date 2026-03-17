# IAMSpy Examples

Real GCP Python scripts. Run `iamspy scan` on each one to see exactly which IAM permissions it requires.

```bash
pip install -e ..
```

---

## Scan all examples at once

```
$ iamspy scan examples/
```

```
examples/bigquery_pipeline.py:9: load_table_from_uri → bigquery.jobs.create, bigquery.tables.updateData
examples/bigquery_pipeline.py:18: get_table → bigquery.tables.get
examples/bigquery_pipeline.py:33: query → bigquery.jobs.create
examples/bigquery_pipeline.py:41: extract_table → bigquery.jobs.create, bigquery.tables.export
examples/kms_encrypt_decrypt.py:12: create_key_ring → cloudkms.keyRings.create
examples/kms_encrypt_decrypt.py:22: create_crypto_key → cloudkms.cryptoKeys.create
examples/kms_encrypt_decrypt.py:38: encrypt → cloudkms.cryptoKeyVersions.useToEncrypt
examples/kms_encrypt_decrypt.py:54: decrypt → cloudkms.cryptoKeyVersions.useToDecrypt
examples/secret_manager.py:9: create_secret → secretmanager.secrets.create
examples/secret_manager.py:23: add_secret_version → secretmanager.versions.add
examples/secret_manager.py:33: access_secret_version → secretmanager.versions.access
examples/secret_manager.py:42: delete_secret → secretmanager.secrets.delete
examples/storage_pipeline.py:8: get_bucket → storage.buckets.get
examples/storage_pipeline.py:10: upload_from_filename → storage.objects.create
examples/storage_pipeline.py:16: get_bucket → storage.buckets.get
examples/storage_pipeline.py:18: download_to_filename → storage.objects.get
examples/storage_pipeline.py:26: get_bucket → storage.buckets.get
examples/storage_pipeline.py:28: get_bucket → storage.buckets.get
examples/storage_pipeline.py:29: copy_blob → storage.objects.create, storage.objects.get
examples/storage_pipeline.py:35: list_blobs → storage.objects.list

20 finding(s)
```

---

## [kms_encrypt_decrypt.py](kms_encrypt_decrypt.py)

Creates a key ring and symmetric key, then encrypts and decrypts a message.

```
$ iamspy scan examples/kms_encrypt_decrypt.py
```

```
examples/kms_encrypt_decrypt.py
    12  key_ring = client.create_key_ring(
        → cloudkms.keyRings.create

    22  key = client.create_crypto_key(
        → cloudkms.cryptoKeys.create

    38  response = client.encrypt(
        → cloudkms.cryptoKeyVersions.useToEncrypt

    54  response = client.decrypt(request={"name": key_name, "ciphertext": ciphertext})
        → cloudkms.cryptoKeyVersions.useToDecrypt

──────────────────────────────────────────────────
1 file(s), 4 finding(s)
Services: kms

Required permissions:
  • cloudkms.cryptoKeyVersions.useToDecrypt
  • cloudkms.cryptoKeyVersions.useToEncrypt
  • cloudkms.cryptoKeys.create
  • cloudkms.keyRings.create
```

---

## [secret_manager.py](secret_manager.py)

Full secret lifecycle: create, add a version, access the payload, delete.

```
$ iamspy scan examples/secret_manager.py
```

```
examples/secret_manager.py
     9  secret = client.create_secret(
        → secretmanager.secrets.create

    23  version = client.add_secret_version(
        → secretmanager.versions.add

    33  response = client.access_secret_version(request={"name": name})
        → secretmanager.versions.access

    42  client.delete_secret(request={"name": name})
        → secretmanager.secrets.delete

──────────────────────────────────────────────────
1 file(s), 4 finding(s)
Services: secretmanager

Required permissions:
  • secretmanager.secrets.create
  • secretmanager.secrets.delete
  • secretmanager.versions.access
  • secretmanager.versions.add
```

---

## [bigquery_pipeline.py](bigquery_pipeline.py)

ETL pipeline: load a JSON file from GCS, run an aggregation query, export results back to GCS.

```
$ iamspy scan examples/bigquery_pipeline.py
```

```
examples/bigquery_pipeline.py
     9  job = client.load_table_from_uri(
        → bigquery.jobs.create, bigquery.tables.updateData
        ⚠ conditional: bigquery.tables.create

    18  table = client.get_table(destination)
        → bigquery.tables.get

    33  rows = list(client.query(query).result())
        → bigquery.jobs.create
        ⚠ conditional: bigquery.tables.getData, bigquery.tables.create

    41  job = client.extract_table(source, gcs_uri)
        → bigquery.jobs.create, bigquery.tables.export

──────────────────────────────────────────────────
1 file(s), 4 finding(s)
Services: bigquery

Required permissions:
  • bigquery.jobs.create
  • bigquery.tables.export
  • bigquery.tables.get
  • bigquery.tables.updateData
  ⚠ bigquery.tables.create (conditional)
  ⚠ bigquery.tables.getData (conditional)
```

---

## [storage_pipeline.py](storage_pipeline.py)

Upload, download, copy, list, and delete objects across Cloud Storage buckets.

```
$ iamspy scan examples/storage_pipeline.py
```

```
examples/storage_pipeline.py
     8  bucket = client.get_bucket(bucket_name)
        → storage.buckets.get

    10  blob.upload_from_filename(source_path)
        → storage.objects.create
        ⚠ conditional: storage.objects.update

    16  bucket = client.get_bucket(bucket_name)
        → storage.buckets.get

    18  blob.download_to_filename(destination_path)
        → storage.objects.get

    26  source_bucket = client.get_bucket(src_bucket)
        → storage.buckets.get

    28  destination_bucket = client.get_bucket(dst_bucket)
        → storage.buckets.get

    29  source_bucket.copy_blob(source, destination_bucket, dst_blob)
        → storage.objects.create, storage.objects.get
        ⚠ conditional: storage.objects.delete

    35  blobs = client.list_blobs(bucket_name, prefix=prefix)
        → storage.objects.list

──────────────────────────────────────────────────
1 file(s), 8 finding(s)
Services: storage

Required permissions:
  • storage.buckets.get
  • storage.objects.create
  • storage.objects.get
  • storage.objects.list
  ⚠ storage.objects.delete (conditional)
  ⚠ storage.objects.update (conditional)
```

---

## JSON output

For use in CI pipelines or IAM policy automation:

```
$ iamspy scan --json examples/kms_encrypt_decrypt.py
```

```json
[
  {
    "file": "examples/kms_encrypt_decrypt.py",
    "line": 12,
    "method": "create_key_ring",
    "service_id": ["kms"],
    "service": ["kms"],
    "class": ["KeyManagementServiceAsyncClient", "KeyManagementServiceClient"],
    "permissions": ["cloudkms.keyRings.create"],
    "conditional": [],
    "status": "mapped"
  },
  {
    "file": "examples/kms_encrypt_decrypt.py",
    "line": 22,
    "method": "create_crypto_key",
    "permissions": ["cloudkms.cryptoKeys.create"],
    "conditional": [],
    "status": "mapped"
  },
  {
    "file": "examples/kms_encrypt_decrypt.py",
    "line": 38,
    "method": "encrypt",
    "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
    "conditional": [],
    "status": "mapped"
  },
  {
    "file": "examples/kms_encrypt_decrypt.py",
    "line": 54,
    "method": "decrypt",
    "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
    "conditional": [],
    "status": "mapped"
  }
]
```
