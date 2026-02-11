#!/bin/bash
# Deploy chatboti FastAPI app
# Usage: ./chatboti-deploy.sh [--ssl]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables from .env if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    echo "Loading environment from .env file..."
    set -a  # automatically export all variables
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Provider configuration (can override with environment variables)
PROVIDER="${DEPLOY_VM_PROVIDER:-aws}"
REGION="${AWS_REGION:-ap-southeast-2}"
VM_SIZE="${VM_SIZE:-t3.small}"
IAM_ROLE="${IAM_ROLE:-}"
APP_MODULE="chatboti.server:app"
APP_NAME="chatboti"
PORT=8000
WORKERS=2

# Build common deploy arguments
COMMON_ARGS=(
    chatboti
    "$SCRIPT_DIR/../chatboti"
    --provider-name "$PROVIDER"
    --region "$REGION"
    --vm-size "$VM_SIZE"
    --app-module "$APP_MODULE"
    --app-name "$APP_NAME"
    --port "$PORT"
    --workers "$WORKERS"
)

# Add IAM role if specified (AWS only)
if [ -n "$IAM_ROLE" ]; then
    COMMON_ARGS+=(--iam-role "$IAM_ROLE")
    echo "Using IAM role: $IAM_ROLE"
fi

if [ "$1" = "--ssl" ]; then
    echo "Deploying chatboti to $PROVIDER with SSL (chatboti.io)"
    uv run deploy-vm fastapi deploy \
        "${COMMON_ARGS[@]}" \
        --domain chatboti.io \
        --email apposite@gmail.com
else
    echo "Deploying chatboti to $PROVIDER (IP-only, no SSL)"
    uv run deploy-vm fastapi deploy \
        "${COMMON_ARGS[@]}" \
        --no-ssl
fi

echo ""
echo "Deployment complete!"
echo "Instance details saved to: chatboti.instance.json"
echo ""
echo "Useful commands:"
echo "  Status:  uv run deploy-vm fastapi status chatboti"
echo "  Logs:    uv run deploy-vm fastapi logs chatboti"
echo "  Restart: uv run deploy-vm fastapi restart chatboti"
echo "  Verify:  uv run deploy-vm instance verify chatboti"
