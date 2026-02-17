#!/bin/bash
# Deploy chatboti FastAPI app

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables from .env if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    echo "Loading environment from .env file..."
    set -a  # automatically export all variables
    source "$SCRIPT_DIR/.env"
    set +a
fi

echo "Deploying chatboti (IP-only, no SSL)"
uv run deploy-vm fastapi deploy \
    chatboti \
    "$SCRIPT_DIR/../chatboti" \
    --command "uv run --no-sync uvicorn chatboti.server:app --host 0.0.0.0 --port 8000 --workers 2" \
    --app-name "chatboti" \
    --port 8000 \
    --no-ssl

echo ""
echo "Deployment complete!"
echo "Instance details saved to: chatboti.instance.json"
echo ""
echo "Useful commands:"
echo "  Status:  uv run deploy-vm fastapi status chatboti"
echo "  Logs:    uv run deploy-vm fastapi logs chatboti"
echo "  Restart: uv run deploy-vm fastapi restart chatboti"
echo "  Verify:  uv run deploy-vm instance verify chatboti"
