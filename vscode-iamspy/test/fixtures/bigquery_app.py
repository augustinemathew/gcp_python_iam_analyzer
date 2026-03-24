"""Sample BigQuery application — used by test_scanner_real.py."""

from google.cloud import bigquery

client = bigquery.Client(project="my-project")

# Run a query
query_job = client.query("SELECT name, value FROM dataset.table WHERE id = @id")
rows = query_job.result()

# Copy a table
job = client.copy_table("src.table", "dst.table")

# Get a dataset reference (local helper, no API call)
ds = client.dataset("analytics")

# Insert rows
table_ref = client.get_table("project.dataset.table")
errors = client.insert_rows_json(table_ref, [{"col": "val"}])
