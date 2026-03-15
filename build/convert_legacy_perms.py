"""Convert legacy iam_perms.py to iam_permissions.json.

One-time migration script. Maps display-name-keyed entries to service_id-keyed format.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to path so we can import the legacy module
sys.path.insert(0, str(Path(__file__).parent.parent))

from iam_perms import _EXPLICIT

# Display name → service_id mapping
_DISPLAY_TO_SERVICE_ID = {
    "Cloud Storage": "storage",
    "BigQuery": "bigquery",
    "Pub/Sub": "pubsub",
    "Secret Manager": "secretmanager",
    "Firestore": "firestore",
    "Cloud Logging": "logging",
    "Cloud KMS": "kms",
    "Spanner": "spanner",
    "Bigtable": "bigtable",
    "Datastore": "datastore",
    "Cloud Monitoring": "monitoring",
    "Cloud Tasks": "cloudtasks",
    "Cloud Functions": "cloudfunctions",
    "Compute Engine": "compute",
    "GKE": "container",
    "Vertex AI": "aiplatform",
    "Cloud Translation": "translate",
    "Cloud Vision": "vision",
    "Cloud Speech": "speech",
    "Cloud TTS": "texttospeech",
    "Cloud NLP": "language",
    "Dialogflow": "dialogflow",
    "Memorystore": "redis",
    "Cloud Scheduler": "cloudscheduler",
    "Cloud Run": "run",
    "Cloud DNS": "dns",
    "IAM": "iam",
    "Resource Manager": "resourcemanager",
    "Cloud Billing": "billing",
    "Cloud SQL": "cloudsql",
}


def convert():
    result = {}
    for (service_display, method_name, class_name), perms in _EXPLICIT.items():
        service_id = _DISPLAY_TO_SERVICE_ID.get(service_display)
        if service_id is None:
            print(f"WARNING: Unknown service display name: {service_display}", file=sys.stderr)
            continue

        # Build key: service_id.class_name.method_name or service_id.*.method_name
        if class_name:
            key = f"{service_id}.{class_name}.{method_name}"
        else:
            key = f"{service_id}.*.{method_name}"

        # Split permissions into required and conditional (? prefix)
        required = [p for p in perms if not p.startswith("?")]
        conditional = [p.lstrip("?") for p in perms if p.startswith("?")]

        is_local_helper = len(required) == 0 and len(conditional) == 0

        entry = {
            "permissions": required,
            "conditional": conditional,
            "local_helper": is_local_helper,
        }
        result[key] = entry

    return result


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "iam_permissions.json"
    data = convert()
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"Wrote {len(data)} entries to {output}", file=sys.stderr)

    # Stats
    services = set()
    mapped = 0
    helpers = 0
    for key, entry in data.items():
        services.add(key.split(".")[0])
        if entry["local_helper"]:
            helpers += 1
        elif entry["permissions"]:
            mapped += 1
    print(f"  Services: {len(services)}", file=sys.stderr)
    print(f"  Mapped (with permissions): {mapped}", file=sys.stderr)
    print(f"  Local helpers: {helpers}", file=sys.stderr)


if __name__ == "__main__":
    main()
