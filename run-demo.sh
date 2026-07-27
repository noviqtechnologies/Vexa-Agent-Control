#!/usr/bin/env bash
# AgentWall Dashboard Launcher (Bash - macOS / Linux)
# Usage: ./run-demo.sh

set -e

DASHBOARD_URL="http://localhost:8081"
LOGIN_EMAIL="admin"

# Resolve compose file relative to this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/dashboard/docker-compose.yml"

# Terminal colour codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
GRAY='\033[0;37m'
DARK_GRAY='\033[0;90m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "  ${CYAN}Building and starting AgentWall Dashboard...${NC}"
echo ""

docker compose -f "$COMPOSE_FILE" up -d --build

if [ $? -ne 0 ]; then
    echo ""
    echo -e "  ${RED}[ERROR] docker compose failed. Check the output above.${NC}"
    exit 1
fi

# Wait for the dashboard API to become healthy
echo ""
echo -e "  ${CYAN}Waiting for services to become healthy...${NC}"

MAX_ATTEMPTS=30
ATTEMPT=0
READY=false

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    sleep 3
    ATTEMPT=$((ATTEMPT + 1))
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:8400/healthz" 2>/dev/null || echo "000")
    if [ "$HTTP_STATUS" = "200" ]; then
        READY=true
        break
    fi
    echo -e "  ${DARK_GRAY}[$ATTEMPT/$MAX_ATTEMPTS] Still starting...${NC}"
done

echo ""

if [ "$READY" = false ]; then
    echo -e "  ${YELLOW}[WARN] API did not respond after $((MAX_ATTEMPTS * 3))s.${NC}"
    echo -e "  ${YELLOW}Check logs: docker compose -f $COMPOSE_FILE logs${NC}"
fi

# Fetch the bootstrap token from container logs
# The API prints it on first boot when no auth providers are configured
BOOTSTRAP_TOKEN=$(docker compose -f "$COMPOSE_FILE" logs dashboard-api 2>&1 | \
    grep -oP 'Bootstrap Token:\s+\K\S+' | tail -1)

# Print access summary banner
LINE="--------------------------------------------------------------"
echo -e "  ${DARK_GRAY}$LINE${NC}"
echo ""
echo -e "   ${GREEN}AgentWall Dashboard is ready!${NC}"
echo ""
echo -e "   ${GRAY}Dashboard URL   ${NC}${YELLOW}$DASHBOARD_URL${NC}"
echo ""
echo -e "   ${GRAY}Login Email     ${NC}${CYAN}$LOGIN_EMAIL${NC}"
echo ""
if [ -n "$BOOTSTRAP_TOKEN" ]; then
    echo -e "   ${GRAY}Bootstrap Token ${NC}${GREEN}$BOOTSTRAP_TOKEN${NC}"
else
    echo -e "   ${GRAY}Bootstrap Token ${NC}${YELLOW}(auth provider configured - use your credentials)${NC}"
fi
echo ""
echo -e "  ${DARK_GRAY}$LINE${NC}"
echo ""
echo -e "   ${DARK_GRAY}Tail logs : docker compose -f $COMPOSE_FILE logs -f${NC}"
echo -e "   ${DARK_GRAY}Stop      : docker compose -f $COMPOSE_FILE down${NC}"
echo ""
