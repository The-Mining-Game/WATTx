#!/bin/bash
#
# WATTx Seed Node Setup Script
# This script automates the deployment of a WATTx seed node
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
WATTX_USER="${WATTX_USER:-wattx}"
WATTX_DATA_DIR="/home/${WATTX_USER}/.wattx"
WATTX_BIN_DIR="/usr/local/bin"
WATTX_PORT=18888
WATTX_RPC_PORT=18890

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   WATTx Seed Node Setup Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Parse arguments
SEED_NUMBER=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --seed-number)
            SEED_NUMBER="$2"
            shift 2
            ;;
        --user)
            WATTX_USER="$2"
            WATTX_DATA_DIR="/home/${WATTX_USER}/.wattx"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --seed-number N   Seed node number (1, 2, or 3)"
            echo "  --user USERNAME   User to run wattxd as (default: wattx)"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Prompt for seed number if not provided
if [[ -z "$SEED_NUMBER" ]]; then
    echo -e "${YELLOW}Which seed node is this? (1, 2, or 3)${NC}"
    read -p "Seed number: " SEED_NUMBER
fi

if [[ ! "$SEED_NUMBER" =~ ^[1-3]$ ]]; then
    echo -e "${RED}Invalid seed number. Must be 1, 2, or 3${NC}"
    exit 1
fi

echo
echo -e "${GREEN}[1/7] Creating wattx user...${NC}"
if id "$WATTX_USER" &>/dev/null; then
    echo "User $WATTX_USER already exists"
else
    useradd -m -s /bin/bash "$WATTX_USER"
    echo "Created user $WATTX_USER"
fi

echo
echo -e "${GREEN}[2/7] Creating data directory...${NC}"
mkdir -p "$WATTX_DATA_DIR"
chown -R "$WATTX_USER:$WATTX_USER" "$WATTX_DATA_DIR"
echo "Created $WATTX_DATA_DIR"

echo
echo -e "${GREEN}[3/7] Checking for binaries...${NC}"
if [[ ! -f "${WATTX_BIN_DIR}/wattxd" ]]; then
    echo -e "${RED}wattxd not found in ${WATTX_BIN_DIR}${NC}"
    echo "Please copy wattxd and wattx-cli to ${WATTX_BIN_DIR} first"
    exit 1
fi
chmod +x "${WATTX_BIN_DIR}/wattxd" "${WATTX_BIN_DIR}/wattx-cli"
echo "Binaries found and made executable"

echo
echo -e "${GREEN}[4/7] Generating RPC credentials...${NC}"
RPC_PASSWORD=$(openssl rand -hex 32)
RPC_USER="wattxrpc"
echo "Generated secure RPC password"

echo
echo -e "${GREEN}[5/7] Creating configuration file...${NC}"

# Build addnode list (exclude self)
ADDNODES=""
for i in 1 2 3; do
    if [[ "$i" != "$SEED_NUMBER" ]]; then
        ADDNODES="${ADDNODES}addnode=seed${i}.wattxchange.app\n"
    fi
done

cat > "${WATTX_DATA_DIR}/wattx.conf" << EOF
# WATTx Seed Node Configuration
# Seed Node ${SEED_NUMBER} - seed${SEED_NUMBER}.wattxchange.app

# Network
server=1
daemon=0
listen=1
port=${WATTX_PORT}
maxconnections=256

# RPC Configuration
rpcuser=${RPC_USER}
rpcpassword=${RPC_PASSWORD}
rpcport=${WATTX_RPC_PORT}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Seed Nodes (other seeds)
$(echo -e "$ADDNODES")

# Performance
dbcache=512
maxmempool=300

# Logging
debug=0
printtoconsole=0
logips=1
EOF

chown "$WATTX_USER:$WATTX_USER" "${WATTX_DATA_DIR}/wattx.conf"
chmod 600 "${WATTX_DATA_DIR}/wattx.conf"
echo "Created ${WATTX_DATA_DIR}/wattx.conf"

echo
echo -e "${GREEN}[6/7] Creating systemd service...${NC}"
cat > /etc/systemd/system/wattxd.service << EOF
[Unit]
Description=WATTx Seed Node
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=${WATTX_USER}
Group=${WATTX_USER}

ExecStart=${WATTX_BIN_DIR}/wattxd -datadir=${WATTX_DATA_DIR} -conf=${WATTX_DATA_DIR}/wattx.conf
ExecStop=${WATTX_BIN_DIR}/wattx-cli -datadir=${WATTX_DATA_DIR} stop

Restart=on-failure
RestartSec=30
TimeoutStartSec=60
TimeoutStopSec=120

# Hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "Created systemd service"

echo
echo -e "${GREEN}[7/7] Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow ${WATTX_PORT}/tcp comment "WATTx P2P"
    echo "Opened port ${WATTX_PORT} in UFW"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${WATTX_PORT}/tcp
    firewall-cmd --reload
    echo "Opened port ${WATTX_PORT} in firewalld"
else
    echo -e "${YELLOW}No firewall detected. Make sure port ${WATTX_PORT} is open${NC}"
fi

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo -e "Seed Node: ${YELLOW}seed${SEED_NUMBER}.wattxchange.app${NC}"
echo -e "Data Dir:  ${YELLOW}${WATTX_DATA_DIR}${NC}"
echo -e "P2P Port:  ${YELLOW}${WATTX_PORT}${NC}"
echo -e "RPC Port:  ${YELLOW}${WATTX_RPC_PORT}${NC}"
echo
echo -e "${GREEN}Commands:${NC}"
echo "  Start:   sudo systemctl start wattxd"
echo "  Stop:    sudo systemctl stop wattxd"
echo "  Status:  sudo systemctl status wattxd"
echo "  Logs:    sudo journalctl -u wattxd -f"
echo "  Enable:  sudo systemctl enable wattxd"
echo
echo -e "${GREEN}CLI Usage:${NC}"
echo "  sudo -u ${WATTX_USER} wattx-cli -datadir=${WATTX_DATA_DIR} getblockchaininfo"
echo
echo -e "${YELLOW}Don't forget to set up DNS:${NC}"
echo "  seed${SEED_NUMBER}.wattxchange.app -> $(curl -s ifconfig.me 2>/dev/null || echo '<this-server-ip>')"
echo
echo -e "${GREEN}Start the node now? [y/N]${NC}"
read -p "" START_NOW
if [[ "$START_NOW" =~ ^[Yy]$ ]]; then
    systemctl enable wattxd
    systemctl start wattxd
    echo
    echo -e "${GREEN}WATTx node started!${NC}"
    sleep 2
    systemctl status wattxd --no-pager
fi
