#!/bin/bash
# Deploy chatboti FastAPI app

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

set -a
source "$SCRIPT_DIR/.env"
set +a

uv run deployvm uv deploy \
    chatboti2 \
    "$SCRIPT_DIR/../chatboti" \
    "uv run chatboti server --port 8000" \
    --app-name "chatboti2" \
    --port 8000 \
    --no-ssl \
    --provider vultr \
    --region ewr \
    --vm-size vc2-1c-1gb


echo "Useful commands:"
echo "  Status:  uv run deployvm uv status chatboti"
echo "  Logs:    uv run deployvm uv logs chatboti"
echo "  Verify:  uv run deployvm instance verify chatboti"
