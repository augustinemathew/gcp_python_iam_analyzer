"""BigQuery ETL pipeline: load data from GCS, run a query, export results."""

from google.cloud import bigquery


def load_from_gcs(project_id: str, dataset_id: str, table_id: str, gcs_uri: str):
    client = bigquery.Client(project=project_id)
    destination = f"{project_id}.{dataset_id}.{table_id}"
    job = client.load_table_from_uri(
        gcs_uri,
        destination,
        job_config=bigquery.LoadJobConfig(
            autodetect=True,
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        ),
    )
    job.result()
    table = client.get_table(destination)
    print(f"Loaded {table.num_rows} rows to {destination}")
    return table


def run_query(project_id: str, dataset_id: str) -> list:
    client = bigquery.Client(project=project_id)
    query = f"""
        SELECT user_id, COUNT(*) as event_count
        FROM `{project_id}.{dataset_id}.events`
        WHERE DATE(timestamp) = CURRENT_DATE()
        GROUP BY user_id
        ORDER BY event_count DESC
        LIMIT 100
    """
    rows = list(client.query(query).result())
    print(f"Query returned {len(rows)} rows")
    return rows


def export_to_gcs(project_id: str, dataset_id: str, table_id: str, gcs_uri: str):
    client = bigquery.Client(project=project_id)
    source = f"{project_id}.{dataset_id}.{table_id}"
    job = client.extract_table(source, gcs_uri)
    job.result()
    print(f"Exported {source} to {gcs_uri}")
