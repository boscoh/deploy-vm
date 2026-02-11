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

APP_MODULE="chatboti.server:app"
APP_NAME="chatboti"
PORT=8000
WORKERS=2

# Build common deploy arguments
COMMON_ARGS=(
    chatboti
    "$SCRIPT_DIR/../chatboti"
    --app-module "$APP_MODULE"
    --app-name "$APP_NAME"
    --port "$PORT"
    --workers "$WORKERS"
)

if [ "$1" = "--ssl" ]; then
    echo "Deploying chatboti with SSL (chatboti.io)"
    uv run deploy-vm fastapi deploy \
        "${COMMON_ARGS[@]}" \
        --domain chatboti.io \
        --email apposite@gmail.com
else
    echo "Deploying chatboti (IP-only, no SSL)"
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
