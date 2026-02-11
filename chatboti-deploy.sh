#!/bin/bash
# Deploy chatboti FastAPI app to AWS
# Usage: ./chatboti-deploy.sh [--ssl]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# AWS Configuration (can override with environment variables)
PROVIDER="${PROVIDER:-aws}"
REGION="${AWS_REGION:-ap-southeast-2}"
VM_SIZE="${VM_SIZE:-t3.small}"
APP_MODULE="chatboti.server:app"
APP_NAME="chatboti"
PORT=8000
WORKERS=2

if [ "$1" = "--ssl" ]; then
    echo "Deploying chatboti to AWS with SSL (chatboti.io)"
    uv run deploy-vm fastapi deploy \
        chatboti \
        "$SCRIPT_DIR/../chatboti" \
        --provider "$PROVIDER" \
        --region "$REGION" \
        --vm-size "$VM_SIZE" \
        --app-module "$APP_MODULE" \
        --app-name "$APP_NAME" \
        --port "$PORT" \
        --workers "$WORKERS" \
        --domain chatboti.io \
        --email apposite@gmail.com
else
    echo "Deploying chatboti to AWS (IP-only, no SSL)"
    uv run deploy-vm fastapi deploy \
        chatboti \
        "$SCRIPT_DIR/../chatboti" \
        --provider "$PROVIDER" \
        --region "$REGION" \
        --vm-size "$VM_SIZE" \
        --app-module "$APP_MODULE" \
        --app-name "$APP_NAME" \
        --port "$PORT" \
        --workers "$WORKERS" \
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
