"""BigQuery billing export tool — query GCP billing data."""

from __future__ import annotations

from google.cloud import bigquery


def query_billing(
    project_id: str,
    billing_table: str = "",
    days: int = 30,
) -> dict:
    """Query the BigQuery billing export for cost by service.

    Args:
        project_id: The GCP project ID to query billing for.
        billing_table: Fully qualified BigQuery table name, e.g.
            ``project.billing_export.gcp_billing_export_v1_XXXXXX``.
            If empty, attempts to auto-discover the billing export table
            in the ``billing_export`` dataset.
        days: Number of days to look back (default 30).

    Returns:
        A dict with:
          - "total_cost": total spend in USD
          - "by_service": list of {"service": str, "cost": float} sorted desc
          - "top_skus": top 20 SKUs by cost
          - "currency": the currency code
    """
    client = bigquery.Client(project=project_id)

    if not billing_table:
        billing_table = _discover_billing_table(client, project_id)
        if not billing_table:
            return {
                "error": "No billing export table found. Billing export may not "
                "be configured. See: https://cloud.google.com/billing/docs/"
                "how-to/export-data-bigquery",
                "total_cost": 0,
                "by_service": [],
                "top_skus": [],
                "currency": "USD",
            }

    query = f"""
    SELECT
        service.description AS service,
        sku.description AS sku,
        SUM(cost) + SUM(IFNULL(
            (SELECT SUM(c.amount) FROM UNNEST(credits) c), 0
        )) AS net_cost,
        currency
    FROM `{billing_table}`
    WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND project.id = @project_id
    GROUP BY service, sku, currency
    ORDER BY net_cost DESC
    """

    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("project_id", "STRING", project_id),
        ]
    )
    rows = list(client.query(query, job_config=job_config).result())

    if not rows:
        return {"total_cost": 0, "by_service": [], "top_skus": [], "currency": "USD"}

    currency = rows[0].currency if rows else "USD"

    by_service: dict[str, float] = {}
    for row in rows:
        by_service[row.service] = by_service.get(row.service, 0) + row.net_cost

    return {
        "total_cost": round(sum(by_service.values()), 2),
        "by_service": sorted(
            [{"service": s, "cost": round(c, 2)} for s, c in by_service.items()],
            key=lambda x: x["cost"],
            reverse=True,
        ),
        "top_skus": [
            {"service": r.service, "sku": r.sku, "cost": round(r.net_cost, 2)}
            for r in rows[:20]
        ],
        "currency": currency,
    }


def _discover_billing_table(client: bigquery.Client, project_id: str) -> str | None:
    """Try to find a billing export table in the project.

    Looks for tables matching ``gcp_billing_export_*`` in a dataset called
    ``billing_export``. Returns the fully qualified table name or ``None``.
    """
    dataset_ref = f"{project_id}.billing_export"
    try:
        tables = list(client.list_tables(dataset_ref, max_results=50))
    except Exception:
        return None

    for table in tables:
        if table.table_id.startswith("gcp_billing_export"):
            return f"{project_id}.billing_export.{table.table_id}"
    return None
