#!/bin/bash
#
# WATTx Seed Node Deployment Script
# Run this from your build machine to deploy to a remote server
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build/bin"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   WATTx Seed Node Deployment${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Parse arguments
REMOTE_HOST=""
REMOTE_USER="root"
SSH_PORT=22
SEED_NUMBER=""

print_usage() {
    echo "Usage: $0 -h HOST [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -h, --host HOST       Remote server hostname or IP"
    echo ""
    echo "Options:"
    echo "  -u, --user USER       SSH user (default: root)"
    echo "  -p, --port PORT       SSH port (default: 22)"
    echo "  -n, --seed-number N   Seed node number (1, 2, or 3)"
    echo "  -b, --build-dir DIR   Path to build binaries"
    echo "  --help                Show this help"
    echo ""
    echo "Example:"
    echo "  $0 -h seed1.wattxchange.app -n 1"
    echo "  $0 -h 192.168.1.100 -u ubuntu -p 2222 -n 2"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            REMOTE_HOST="$2"
            shift 2
            ;;
        -u|--user)
            REMOTE_USER="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -n|--seed-number)
            SEED_NUMBER="$2"
            shift 2
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

if [[ -z "$REMOTE_HOST" ]]; then
    echo -e "${RED}Error: Remote host is required${NC}"
    echo
    print_usage
    exit 1
fi

# Check for binaries
if [[ ! -f "${BUILD_DIR}/wattxd" ]]; then
    echo -e "${RED}Error: wattxd not found at ${BUILD_DIR}/wattxd${NC}"
    echo "Build the project first or specify --build-dir"
    exit 1
fi

if [[ ! -f "${BUILD_DIR}/wattx-cli" ]]; then
    echo -e "${RED}Error: wattx-cli not found at ${BUILD_DIR}/wattx-cli${NC}"
    exit 1
fi

SSH_OPTS="-p ${SSH_PORT}"
SCP_OPTS="-P ${SSH_PORT}"

echo -e "${GREEN}[1/4] Testing SSH connection...${NC}"
if ! ssh ${SSH_OPTS} "${REMOTE_USER}@${REMOTE_HOST}" "echo 'Connection successful'" 2>/dev/null; then
    echo -e "${RED}Failed to connect to ${REMOTE_USER}@${REMOTE_HOST}:${SSH_PORT}${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check if SSH is running on the server"
    echo "  2. Verify firewall allows port ${SSH_PORT}"
    echo "  3. Confirm hostname/IP is correct"
    echo "  4. Check SSH key or password authentication"
    exit 1
fi
echo "SSH connection OK"

echo
echo -e "${GREEN}[2/4] Copying binaries...${NC}"
echo "Copying wattxd and wattx-cli to ${REMOTE_HOST}..."
scp ${SCP_OPTS} "${BUILD_DIR}/wattxd" "${BUILD_DIR}/wattx-cli" "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"
echo "Binaries copied to /tmp/"

echo
echo -e "${GREEN}[3/4] Copying setup script...${NC}"
scp ${SCP_OPTS} "${SCRIPT_DIR}/setup-seed-node.sh" "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"
echo "Setup script copied"

echo
echo -e "${GREEN}[4/4] Running setup on remote server...${NC}"
echo

# Build setup command
SETUP_CMD="chmod +x /tmp/setup-seed-node.sh && "
SETUP_CMD+="mv /tmp/wattxd /tmp/wattx-cli /usr/local/bin/ && "
SETUP_CMD+="/tmp/setup-seed-node.sh"

if [[ -n "$SEED_NUMBER" ]]; then
    SETUP_CMD+=" --seed-number ${SEED_NUMBER}"
fi

# Run setup (need sudo if not root)
if [[ "$REMOTE_USER" == "root" ]]; then
    ssh ${SSH_OPTS} "${REMOTE_USER}@${REMOTE_HOST}" "${SETUP_CMD}"
else
    ssh ${SSH_OPTS} -t "${REMOTE_USER}@${REMOTE_HOST}" "sudo bash -c '${SETUP_CMD}'"
fi

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo -e "Server: ${YELLOW}${REMOTE_HOST}${NC}"
echo
echo -e "${GREEN}To check status:${NC}"
echo "  ssh ${SSH_OPTS} ${REMOTE_USER}@${REMOTE_HOST} 'systemctl status wattxd'"
echo
echo -e "${GREEN}To view logs:${NC}"
echo "  ssh ${SSH_OPTS} ${REMOTE_USER}@${REMOTE_HOST} 'journalctl -u wattxd -f'"
