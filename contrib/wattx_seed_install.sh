#!/usr/bin/env bash
# WATTx community seed node installer.
#
#   curl -fsSL https://pools.wattxchange.app/seed.sh | sudo bash
#
# (or straight from the repo's default branch:
#  https://raw.githubusercontent.com/WATTxChain/WATTx/feat/multi-algo-auxpow-merged-mining/contrib/wattx_seed_install.sh)
#
# Not to be confused with contrib/deploy-seed-node.sh, which PUSHES binaries
# from your own build machine to a host you already control. This one is what a
# stranger runs on their own box to join the network.
#
# Installs wattxd as a hardened systemd service that keeps a WATTx mainnet node
# online and reachable, so the network has more than one public seed. It does
# NOT touch wallets, mining, or RPC exposure: the node relays blocks and serves
# peers, nothing else.
#
# Idempotent — re-running upgrades the binary and restarts the service, leaving
# the datadir and config alone.
#
# Debian/Ubuntu, x86_64 or aarch64. On aarch64 there is no published binary yet,
# so it builds from source (slow on small instances; see BUILD note below).
set -euo pipefail

REPO="WATTxChain/WATTx"
P2P_PORT=1337
RPC_PORT=3889
SVC_USER="wattx"
DATADIR="/var/lib/wattx"
BINDIR="/usr/local/bin"
SEEDS=(seed1.wattxchange.app seed2.wattxchange.app seed3.wattxchange.app)

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo bash $0)"
command -v apt-get >/dev/null || die "this installer targets Debian/Ubuntu"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  MODE=binary ;;
  aarch64|arm64) MODE=source ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

# ── swap ─────────────────────────────────────────────────────────────────────
# RandomX block verification wants roughly 400 MB on top of the daemon's own
# footprint. The 1 GB free-tier instances (Oracle E2.1.Micro, GCP e2-micro) OOM
# without swap; 2 GB of swap is the difference between a node that stays up and
# one the kernel kills mid-sync.
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
SWAP_MB=$(free -m | awk '/^Swap:/{print $2}')
if [ "$RAM_MB" -lt 2000 ] && [ "$SWAP_MB" -lt 1000 ] && [ ! -f /swapfile ]; then
  log "only ${RAM_MB} MB RAM and no swap — creating a 2 GB swapfile"
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ── fetch or build the daemon ────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates jq >/dev/null

TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name)
[ -n "$TAG" ] && [ "$TAG" != null ] || die "could not read the latest release tag from GitHub"
log "latest WATTx release: $TAG"

build_from_source() {
  # BUILD note: on a 1 OCPU / 6 GB ARM instance expect 1-3 hours. -j is capped
  # by RAM, not cores: each g++ job on this tree peaks near 1.5 GB, so an
  # over-parallel build dies with "cc1plus: out of memory" partway through.
  log "building $TAG from source (this takes a while)"
  apt-get install -y -qq build-essential cmake pkgconf python3 git \
      libgmp3-dev libevent-dev libboost-dev libsqlite3-dev libsodium-dev >/dev/null
  SRC=/usr/local/src/wattx
  rm -rf "$SRC"; git clone --depth 1 --branch "$TAG" "https://github.com/$REPO.git" "$SRC"
  JOBS=$(( (RAM_MB + SWAP_MB) / 1500 )); [ "$JOBS" -lt 1 ] && JOBS=1
  CORES=$(nproc); [ "$JOBS" -gt "$CORES" ] && JOBS=$CORES
  log "building with -j$JOBS"
  cmake -S "$SRC" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DENABLE_WALLET=OFF >/dev/null
  cmake --build "$SRC/build" -j"$JOBS" --target wattxd wattx-cli
  install -m755 "$SRC/build/bin/wattxd" "$BINDIR/wattxd"
  install -m755 "$SRC/build/bin/wattx-cli" "$BINDIR/wattx-cli"
  find "$SRC/build" -name 'librandomx*.so*' -exec install -m644 {} /usr/local/lib/ \; 2>/dev/null || true
  ldconfig
}

if [ "$MODE" = binary ]; then
  VER=${TAG#v}
  URL="https://github.com/$REPO/releases/download/$TAG/wattx-${VER}-linux64.tar.gz"
  log "downloading $URL"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "$URL" -o "$TMP/wattx.tar.gz" || die "download failed — check that $TAG ships a linux64 asset"
  tar -xzf "$TMP/wattx.tar.gz" -C "$TMP"
  D=$(find "$TMP" -type f -name wattxd -perm -u+x | head -1)
  [ -n "$D" ] || die "no wattxd inside the tarball"
  install -m755 "$D" "$BINDIR/wattxd"
  C=$(find "$TMP" -type f -name wattx-cli -perm -u+x | head -1)
  [ -n "$C" ] && install -m755 "$C" "$BINDIR/wattx-cli"
  # The release ships librandomx.so next to the binaries; without it wattxd
  # will not start.
  find "$TMP" -name 'librandomx*.so*' -exec install -m644 {} /usr/local/lib/ \; 2>/dev/null || true
  ldconfig

  # The published binary is DYNAMICALLY linked and was built on Ubuntu 22.04:
  # it needs libevent 2.1, libsodium23, libsqlite3 and boost 1.74. Ubuntu 24.04
  # ships boost 1.83, so 1.74 simply is not installable there and the binary
  # cannot run — which is why the run check below, not the download, decides
  # whether this path worked.
  log "installing runtime libraries"
  apt-get install -y -qq libevent-2.1-7 libsodium23 libsqlite3-0 >/dev/null 2>&1 || true
  apt-get install -y -qq libboost-filesystem1.74.0 libboost-program-options1.74.0 \
      libboost-thread1.74.0 >/dev/null 2>&1 || true

  if ! LD_LIBRARY_PATH=/usr/local/lib "$BINDIR/wattxd" --version >/dev/null 2>&1; then
    warn "the published binary will not run on this release:"
    LD_LIBRARY_PATH=/usr/local/lib ldd "$BINDIR/wattxd" 2>/dev/null | grep "not found" | sed 's/^/    /'
    warn "falling back to a source build"
    build_from_source
  fi
else
  warn "no published aarch64 binary for $ARCH"
  build_from_source
fi
LD_LIBRARY_PATH=/usr/local/lib "$BINDIR/wattxd" --version >/dev/null 2>&1 \
  || die "wattxd still will not run — stopping before installing a service that cannot start"
log "installed $(LD_LIBRARY_PATH=/usr/local/lib "$BINDIR/wattxd" --version 2>/dev/null | head -1)"

# ── service account, datadir, config ─────────────────────────────────────────
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$DATADIR" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$DATADIR"
chown -R "$SVC_USER:$SVC_USER" "$DATADIR"

if [ ! -f "$DATADIR/wattx.conf" ]; then
  log "writing $DATADIR/wattx.conf"
  RPCPASS=$(head -c32 /dev/urandom | base64 | tr -d '/+=' | head -c32)
  {
    echo "# WATTx community seed node — generated $(date -Is)"
    echo "server=1"
    echo "listen=1"
    echo "daemon=0"
    echo "# a seed serves peers; it holds no keys"
    echo "disablewallet=1"
    echo "maxconnections=125"
    echo "dbcache=$([ "$RAM_MB" -ge 4000 ] && echo 450 || echo 150)"
    echo
    echo "[main]"
    echo "port=$P2P_PORT"
    echo "rpcport=$RPC_PORT"
    echo "rpcbind=127.0.0.1"
    echo "rpcallowip=127.0.0.1"
    echo "rpcuser=wattxrpc"
    echo "rpcpassword=$RPCPASS"
    for s in "${SEEDS[@]}"; do echo "addnode=$s:$P2P_PORT"; done
  } > "$DATADIR/wattx.conf"
  chown "$SVC_USER:$SVC_USER" "$DATADIR/wattx.conf"
  chmod 600 "$DATADIR/wattx.conf"
else
  log "keeping existing $DATADIR/wattx.conf"
fi

# ── systemd ──────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/wattxd.service <<UNIT
[Unit]
Description=WATTx seed node
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
Type=simple
ExecStart=$BINDIR/wattxd -datadir=$DATADIR -conf=$DATADIR/wattx.conf -printtoconsole
Restart=always
RestartSec=15
TimeoutStopSec=180
Environment=LD_LIBRARY_PATH=/usr/local/lib

# The daemon needs nothing outside its datadir.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATADIR

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wattxd >/dev/null
log "wattxd service enabled"

# ── firewall ─────────────────────────────────────────────────────────────────
# A seed nobody can dial is not a seed. Open the P2P port everywhere it might
# be filtered; each step is a no-op when that firewall is not in use.
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$P2P_PORT"/tcp >/dev/null && log "ufw: opened $P2P_PORT/tcp"
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$P2P_PORT"/tcp >/dev/null
  firewall-cmd --reload >/dev/null && log "firewalld: opened $P2P_PORT/tcp"
fi
# Oracle Cloud's Ubuntu images ship an iptables INPUT chain that REJECTs
# everything past ssh, and it survives reboots via netfilter-persistent — this
# is the single most common reason a cloud node looks up but never gets an
# inbound peer.
if command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qE 'REJECT|DROP'; then
  if ! iptables -C INPUT -p tcp --dport "$P2P_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport "$P2P_PORT" -j ACCEPT
    log "iptables: opened $P2P_PORT/tcp"
    command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
  fi
fi

cat <<EOF

WATTx seed node installed.

  status   systemctl status wattxd
  logs     journalctl -u wattxd -f
  height   wattx-cli -datadir=$DATADIR getblockcount
  peers    wattx-cli -datadir=$DATADIR getconnectioncount

Initial sync takes a while; the node starts serving peers as it catches up.

ONE THING LEFT that this script cannot do for you: if this box is behind a
cloud provider's network ACL (Oracle security list, AWS security group, GCP
firewall rule) or a home router, TCP $P2P_PORT must be allowed inbound there
too. Until it is, the node syncs but never accepts an incoming connection —
which is the whole point of a seed. Verify from elsewhere with:

  nc -vz <this-node-public-ip> $P2P_PORT

EOF
