"""Non-GCP Python file — scanner should produce zero findings."""

import pandas as pd

df = pd.read_csv("data.csv")
filtered = df.query("value > 100")
result = filtered.get("column", default=[])

# These look like GCP method names but have no GCP imports
rows = result.list()
client = object()
client.get_bucket("bucket")
client.query("SELECT 1")
