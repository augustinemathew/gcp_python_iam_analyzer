#!/usr/bin/env bash
# Deploy the delegated identity experiment to Cloud Run.
#
# Prerequisites:
#   1. Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET env vars
#   2. gcloud authenticated with project access
#
# Usage:
#   export OAUTH_CLIENT_ID="123456-abc.apps.googleusercontent.com"
#   export OAUTH_CLIENT_SECRET="GOCSPX-..."
#   ./deploy.sh

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-agentengine-478902}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="delegated-id-experiment"
SA_NAME="delegated-id-exp"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "=== Delegated Identity Experiment Deploy ==="
echo "Project:  $PROJECT_ID"
echo "Region:   $REGION"
echo "Service:  $SERVICE_NAME"
echo ""

# --- Validate inputs ---
if [[ -z "${OAUTH_CLIENT_ID:-}" ]]; then
    echo "ERROR: Set OAUTH_CLIENT_ID env var"
    exit 1
fi
if [[ -z "${OAUTH_CLIENT_SECRET:-}" ]]; then
    echo "ERROR: Set OAUTH_CLIENT_SECRET env var"
    exit 1
fi

# --- Create SA (idempotent) ---
echo "1/5  Creating service account..."
gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" 2>/dev/null \
    || gcloud iam service-accounts create "$SA_NAME" \
        --project="$PROJECT_ID" \
        --display-name="Delegated Identity Experiment"

# --- Grant SA permissions ---
echo "2/5  Granting IAM roles..."
# SA needs: list buckets (storage.objectViewer) + read secrets (secretAccessor)
for role in roles/storage.objectViewer; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="$role" \
        --condition=None \
        --quiet
done

# --- Store OAuth secret ---
echo "3/5  Storing OAuth client secret in Secret Manager..."
if gcloud secrets describe oauth-client-secret --project="$PROJECT_ID" 2>/dev/null; then
    echo -n "$OAUTH_CLIENT_SECRET" | gcloud secrets versions add oauth-client-secret \
        --project="$PROJECT_ID" \
        --data-file=-
else
    echo -n "$OAUTH_CLIENT_SECRET" | gcloud secrets create oauth-client-secret \
        --project="$PROJECT_ID" \
        --data-file=- \
        --replication-policy=automatic
fi

gcloud secrets add-iam-policy-binding oauth-client-secret \
    --project="$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet

# --- Deploy to Cloud Run ---
echo "4/5  Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --source=. \
    --service-account="$SA_EMAIL" \
    --allow-unauthenticated \
    --set-env-vars="OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID},PROJECT_ID=${PROJECT_ID}" \
    --memory=256Mi \
    --cpu=1 \
    --max-instances=1 \
    --quiet

# --- Get URL ---
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --format="value(status.url)")

echo ""
echo "5/5  Deployed: $SERVICE_URL"
echo ""
echo "=== IMPORTANT: Update OAuth redirect URI ==="
echo "Go to: https://console.cloud.google.com/apis/credentials"
echo "Edit your OAuth client and add this redirect URI:"
echo "  ${SERVICE_URL}/callback"
echo ""
echo "Then test: open ${SERVICE_URL}"
