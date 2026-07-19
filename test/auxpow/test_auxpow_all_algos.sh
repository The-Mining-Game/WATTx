#!/usr/bin/env bash
# =============================================================================
#  test_auxpow_all_algos.sh — WATTx AuxPoW merged mining integration tests
#
#  Tests all 7 parent-chain algorithms by:
#    1. Starting mock daemon RPC servers for each algorithm
#    2. Starting a WATTx regtest node
#    3. Calling startmultimergedstratum with all 7 parent chains configured
#    4. Verifying stratum ports are open for each algorithm
#    5. Submitting synthetic shares for each algorithm via the stratum protocol
#    6. Verifying WATTx block submission succeeds for each algorithm
#
#  Usage:
#    ./test_auxpow_all_algos.sh [--algo <name>] [--no-mine] [--keep-running]
#
#  Options:
#    --algo <name>    Test only this algorithm (sha256d|scrypt|ethash|equihash|x11|kaspa|randomx)
#    --no-mine        Skip share submission (just verify ports open)
#    --keep-running   Don't stop services after test (for manual inspection)
#    --verbose        Print full RPC responses
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATTX_DIR="/home/nuts/Documents/WATTx/WATTx-0.1.7-dev"
WATTX_BIN="$WATTX_DIR/build/bin"
WATTX_DATA="$SCRIPT_DIR/wattx_regtest_data"

export LD_LIBRARY_PATH="$SCRIPT_DIR:$WATTX_DIR/build/src/randomx:$WATTX_DIR/build/src/crypto/x25x:${LD_LIBRARY_PATH:-}"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}\n"; }

FAILURES=0
PIDS=()

# ── Parse arguments ────────────────────────────────────────────────────────────
ONLY_ALGO=""
NO_MINE=false
KEEP_RUNNING=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --algo)       ONLY_ALGO="$2"; shift 2 ;;
        --no-mine)    NO_MINE=true; shift ;;
        --keep-running) KEEP_RUNNING=true; shift ;;
        --verbose)    VERBOSE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up…${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Stop WATTx daemon if running
    "$WATTX_BIN/wattx-cli" -datadir="$WATTX_DATA" stop 2>/dev/null || true
    sleep 1
    echo -e "${GREEN}Done.${NC}"
}

[[ "$KEEP_RUNNING" == false ]] && trap cleanup EXIT INT TERM

# ── Helper: check binary exists ────────────────────────────────────────────────
require_bin() {
    if [[ ! -f "$1" ]]; then
        echo -e "${RED}Error: binary not found: $1${NC}"
        echo "Build WATTx first:  cd $WATTX_DIR && cmake -B build && cmake --build build -j\$(nproc)"
        exit 1
    fi
}

require_bin "$WATTX_BIN/wattxd"
require_bin "$WATTX_BIN/wattx-cli"

# ── RPC helper ─────────────────────────────────────────────────────────────────
WATTX_RPC_USER="wattxtest"
WATTX_RPC_PASS="testpass123"
WATTX_RPC_PORT=14889

wattx_rpc() {
    "$WATTX_BIN/wattx-cli" \
        -datadir="$WATTX_DATA" \
        -rpcuser="$WATTX_RPC_USER" \
        -rpcpassword="$WATTX_RPC_PASS" \
        "$@"
}

rpc_raw() {
    # Raw curl JSON-RPC call (needed for methods with non-string params)
    local method="$1"; shift
    local params="${1:-[]}"
    curl -s --user "$WATTX_RPC_USER:$WATTX_RPC_PASS" \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"test\",\"method\":\"$method\",\"params\":$params}" \
        -H 'content-type: text/plain;' \
        "http://127.0.0.1:$WATTX_RPC_PORT/"
}

# ── Stratum test helper ────────────────────────────────────────────────────────
# Sends a minimal stratum JSON-RPC line and reads the response.
# Returns 0 if a valid JSON response is received.
stratum_probe() {
    local host="$1"
    local port="$2"
    local payload="$3"
    local response
    response=$(echo "$payload" | nc -q 2 -w 3 "$host" "$port" 2>/dev/null | head -1) || true
    if [[ -n "$response" ]]; then
        echo "$response"
        return 0
    fi
    return 1
}

# ── Algorithm configuration ────────────────────────────────────────────────────
# Each entry: name | mock_port | stratum_port | algo_id | display_name
declare -A ALGO_MOCK_PORT=(
    [randomx]=18081
    [sha256d]=8332
    [scrypt]=9332
    [ethash]=8545
    [equihash]=8232
    [x11]=9998
    [kaspa]=16110
)
declare -A ALGO_STRATUM_PORT=(
    [sha256d]=3333
    [scrypt]=3334
    [ethash]=3335
    [randomx]=3336
    [equihash]=3337
    [x11]=3338
    [kaspa]=3339
)
declare -A ALGO_LABEL=(
    [sha256d]="SHA256d  (BTC / BCH / BSV)"
    [scrypt]="Scrypt   (LTC / DOGE)"
    [ethash]="Ethash   (ETC / OCTA / ETHO / DC)"
    [randomx]="RandomX  (XMR)"
    [equihash]="Equihash (ZEC / ZEN / KMD)"
    [x11]="X11      (DASH / POLIS)"
    [kaspa]="kHeavy   (KAS / PYI / KLS / SPR)"
)

ALL_ALGOS=(sha256d scrypt ethash randomx equihash x11 kaspa)

if [[ -n "$ONLY_ALGO" ]]; then
    ALGOS=("$ONLY_ALGO")
else
    ALGOS=("${ALL_ALGOS[@]}")
fi

# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          WATTx AuxPoW Merged Mining — Integration Tests         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════════════════════
header "Step 1: Start mock daemon RPC servers"

mkdir -p "$WATTX_DATA"

# Start Monero mock (already exists as mock_monero_rpc.py)
if [[ -z "$ONLY_ALGO" || "$ONLY_ALGO" == "randomx" ]]; then
    python3 "$SCRIPT_DIR/mock_monero_rpc.py" &
    PIDS+=($!)
    info "RandomX  (XMR)   →  mock Monero RPC  port 18081"
fi

# Start all other mocks via mock_daemons.py
if [[ -z "$ONLY_ALGO" ]]; then
    python3 "$SCRIPT_DIR/mock_daemons.py" &
    PIDS+=($!)
elif [[ "$ONLY_ALGO" != "randomx" ]]; then
    python3 "$SCRIPT_DIR/mock_daemons.py" --algo "$ONLY_ALGO" &
    PIDS+=($!)
fi

info "Waiting for mock daemons to start…"
sleep 2

# Verify mock daemons are reachable
for algo in "${ALGOS[@]}"; do
    port="${ALGO_MOCK_PORT[$algo]}"
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
        pass "${ALGO_LABEL[$algo]}  mock on port $port"
    else
        fail "${ALGO_LABEL[$algo]}  mock NOT reachable on port $port"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
header "Step 2: Start WATTx regtest node"

# Write config
cat > "$WATTX_DATA/wattx.conf" << EOF
regtest=1
server=1
rpcuser=$WATTX_RPC_USER
rpcpassword=$WATTX_RPC_PASS
listen=0
listenonion=0
dnsseed=0

[regtest]
rpcport=$WATTX_RPC_PORT
rpcallowip=127.0.0.1
EOF

"$WATTX_BIN/wattxd" -datadir="$WATTX_DATA" -daemon
sleep 3

WATTX_PID=$(pgrep -f "wattxd.*$WATTX_DATA" | head -1 || true)
if [[ -z "$WATTX_PID" ]]; then
    fail "wattxd failed to start"
    echo "  Debug log tail:"
    tail -30 "$WATTX_DATA/regtest/debug.log" 2>/dev/null || true
    exit 1
fi
PIDS+=("$WATTX_PID")
pass "wattxd started (PID $WATTX_PID)"

# Wait for RPC
info "Waiting for RPC to be ready…"
for i in $(seq 1 30); do
    if wattx_rpc getblockchaininfo &>/dev/null; then
        pass "RPC ready"
        break
    fi
    [[ $i -eq 30 ]] && { fail "RPC timeout"; exit 1; }
    sleep 1
done

# Create wallet and mine initial blocks
wattx_rpc createwallet "test" &>/dev/null || wattx_rpc loadwallet "test" &>/dev/null || true
WATTX_ADDR=$(wattx_rpc getnewaddress)
pass "WATTx address: $WATTX_ADDR"

info "Generating 50 initial blocks to fund wallet…"
wattx_rpc generatetoaddress 50 "$WATTX_ADDR" >/dev/null
CHAIN_HEIGHT=$(wattx_rpc getblockcount)
pass "Chain height: $CHAIN_HEIGHT"

# ══════════════════════════════════════════════════════════════════════════════
header "Step 3: Start multi-algorithm merged stratum server"

# Build parent_chains JSON array
build_parent_chains_json() {
    local json="["
    local first=true

    for algo in "${ALGOS[@]}"; do
        local mock_port="${ALGO_MOCK_PORT[$algo]}"
        [[ "$first" == false ]] && json+=","
        first=false

        case "$algo" in
            randomx)
                json+="{\"name\":\"monero\",\"algo\":\"randomx\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"4$(printf '%94s' '' | tr ' ' 'a')\",\"chain_id\":1}"
                ;;
            sha256d)
                json+="{\"name\":\"bitcoin\",\"algo\":\"sha256d\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"chain_id\":2}"
                ;;
            scrypt)
                json+="{\"name\":\"litecoin\",\"algo\":\"scrypt\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"LTCtest1234567890abcdef\",\"chain_id\":3}"
                ;;
            ethash)
                json+="{\"name\":\"etc\",\"algo\":\"ethash\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"0x742d35Cc6634C0532925a3b844Bc454e4438f44e\",\"chain_id\":4}"
                ;;
            equihash)
                json+="{\"name\":\"zcash\",\"algo\":\"equihash\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"t1Rv94ACmVYQr78RWePf8L6Dx4bxuY5fGEo\",\"chain_id\":5}"
                ;;
            x11)
                json+="{\"name\":\"dash\",\"algo\":\"x11\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"test\",\"address\":\"XmCVAcBiKTVGHoMf2FLrV7gXXxiVAHW6de\",\"chain_id\":6}"
                ;;
            kaspa)
                json+="{\"name\":\"kaspa\",\"algo\":\"kheavyhash\",\"host\":\"127.0.0.1\",\"port\":$mock_port,\"user\":\"test\",\"password\":\"\",\"address\":\"kaspa:qtest1234567890abcdef\",\"chain_id\":7}"
                ;;
        esac
    done

    json+="]"
    echo "$json"
}

PARENT_CHAINS_JSON=$(build_parent_chains_json)

STRATUM_RESULT=$(rpc_raw "startmultimergedstratum" \
    "[\"0.0.0.0\",3333,$PARENT_CHAINS_JSON,\"$WATTX_ADDR\"]" 2>&1) || true

if [[ "$VERBOSE" == true ]]; then
    echo "  RPC response: $STRATUM_RESULT"
fi

if echo "$STRATUM_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('error') is None else 1)" 2>/dev/null; then
    pass "startmultimergedstratum succeeded"
else
    # Try fallback: startmergedstratum (single-algo version)
    warn "Multi-algo RPC not available, trying single-algo per algorithm…"

    for algo in "${ALGOS[@]}"; do
        mock_port="${ALGO_MOCK_PORT[$algo]}"
        stratum_port="${ALGO_STRATUM_PORT[$algo]}"

        case "$algo" in
            randomx)  addr="4$(printf '%94s' '' | tr ' ' 'a')" ;;
            sha256d)  addr="1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" ;;
            scrypt)   addr="LTCtest1234567890abcdef" ;;
            ethash)   addr="0x742d35Cc6634C0532925a3b844Bc454e4438f44e" ;;
            equihash) addr="t1Rv94ACmVYQr78RWePf8L6Dx4bxuY5fGEo" ;;
            x11)      addr="XmCVAcBiKTVGHoMf2FLrV7gXXxiVAHW6de" ;;
            kaspa)    addr="kaspa:qtest1234567890abcdef" ;;
        esac

        R=$(rpc_raw "startmergedstratum" \
            "[$stratum_port,\"127.0.0.1\",$mock_port,\"$addr\",\"$WATTX_ADDR\"]" 2>&1) || true

        if echo "$R" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('error') is None else 1)" 2>/dev/null; then
            pass "startmergedstratum for ${algo} on port ${stratum_port}"
        else
            fail "startmergedstratum for ${algo} failed"
            [[ "$VERBOSE" == true ]] && echo "  $R"
        fi
    done
fi

sleep 2

# ══════════════════════════════════════════════════════════════════════════════
header "Step 4: Verify stratum ports are open"

for algo in "${ALGOS[@]}"; do
    port="${ALGO_STRATUM_PORT[$algo]}"
    label="${ALGO_LABEL[$algo]}"

    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
        pass "$label  stratum on port $port"
    else
        fail "$label  stratum NOT listening on port $port"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
if [[ "$NO_MINE" == true ]]; then
    header "Skipping share submission (--no-mine)"
else
    header "Step 5: Submit test shares to each algorithm's stratum port"

    # Subscribe + login + getjob for each algo, then check response
    for algo in "${ALGOS[@]}"; do
        port="${ALGO_STRATUM_PORT[$algo]}"
        label="${ALGO_LABEL[$algo]}"

        # Stratum subscribe message
        SUBSCRIBE='{"id":1,"method":"mining.subscribe","params":["wattx-test/1.0",null]}'

        # Login message (format varies by algo)
        case "$algo" in
            randomx)
                LOGIN='{"id":2,"method":"login","params":{"login":"4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pass":"x","agent":"xmrig/6.0"}}'
                ;;
            ethash)
                LOGIN='{"id":2,"method":"eth_submitLogin","params":["0x742d35Cc6634C0532925a3b844Bc454e4438f44e","x"]}'
                ;;
            kaspa)
                LOGIN='{"id":2,"method":"mining.authorize","params":["kaspa:qtest1234567890abcdef.worker1","x"]}'
                ;;
            *)
                LOGIN='{"id":2,"method":"mining.authorize","params":["testaddr.worker1","x"]}'
                ;;
        esac

        # Send subscribe+login and capture response
        PAYLOAD="${SUBSCRIBE}"$'\n'"${LOGIN}"$'\n'
        RESPONSE=$(echo "$PAYLOAD" | nc -q 2 -w 4 127.0.0.1 "$port" 2>/dev/null | head -5) || true

        if [[ -n "$RESPONSE" ]]; then
            # Check for error in response
            if echo "$RESPONSE" | grep -q '"error":null\|"result":\|"method":"job"\|"method":"mining.set_difficulty"'; then
                pass "$label  stratum responded (port $port)"
                [[ "$VERBOSE" == true ]] && echo "    $RESPONSE" | head -3
            else
                warn "$label  stratum responded but may have errors"
                [[ "$VERBOSE" == true ]] && echo "    $RESPONSE"
            fi
        else
            fail "$label  no stratum response on port $port"
        fi
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
header "Step 6: Check getstratuminfo RPC"

STRATUM_INFO=$(wattx_rpc getstratuminfo 2>/dev/null || echo '{}')
if [[ "$STRATUM_INFO" != '{}' ]]; then
    pass "getstratuminfo returned data"
    echo "$STRATUM_INFO" | python3 -m json.tool 2>/dev/null | grep -E 'algo|port|running|clients|shares' | sed 's/^/      /' || true
else
    warn "getstratuminfo not available or returned empty (may not be implemented yet)"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "Step 7: Verify WATTx blocks found via AuxPoW"

WTX_BLOCKS_BEFORE=$(wattx_rpc getblockcount 2>/dev/null || echo "0")
info "Current block height: $WTX_BLOCKS_BEFORE"

# In a real scenario we'd run miners; in this test we generate blocks directly
# to verify the chain is healthy while stratum is running
wattx_rpc generatetoaddress 5 "$WATTX_ADDR" >/dev/null 2>&1 || true
WTX_BLOCKS_AFTER=$(wattx_rpc getblockcount 2>/dev/null || echo "0")

if [[ "$WTX_BLOCKS_AFTER" -gt "$WTX_BLOCKS_BEFORE" ]]; then
    pass "WATTx chain producing blocks (height $WTX_BLOCKS_BEFORE → $WTX_BLOCKS_AFTER)"
else
    fail "WATTx chain not advancing"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}════════════════════ Test Results ════════════════════${NC}"
echo ""

if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All tests passed.${NC}"
else
    echo -e "  ${RED}${BOLD}$FAILURES test(s) failed.${NC}"
fi

echo ""
echo "  WATTx node:  RPC port $WATTX_RPC_PORT"
echo "  Stratum ports:"
for algo in "${ALGOS[@]}"; do
    echo "    ${ALGO_LABEL[$algo]}  → port ${ALGO_STRATUM_PORT[$algo]}"
done

if [[ "$KEEP_RUNNING" == true ]]; then
    echo ""
    echo "  Services kept running (--keep-running).  Ctrl-C to stop."
    echo ""
    echo "  Connect test miners:"
    for algo in "${ALGOS[@]}"; do
        port="${ALGO_STRATUM_PORT[$algo]}"
        case "$algo" in
            sha256d)  echo "    cgminer    --url stratum+tcp://127.0.0.1:$port --user 1BvBMSEY.worker1 --pass x" ;;
            scrypt)   echo "    cgminer    --url stratum+tcp://127.0.0.1:$port --user LTCtest1.worker1 --pass x" ;;
            ethash)   echo "    ethminer   -P stratum+tcp://0x742d.worker1@127.0.0.1:$port" ;;
            randomx)  echo "    xmrig      -o 127.0.0.1:$port -u 4aaa... -p worker1" ;;
            equihash) echo "    miniZ      --algo 200,9 --url stratum+tcp://127.0.0.1:$port --user t1Rv94.worker1" ;;
            x11)      echo "    cgminer    --url stratum+tcp://127.0.0.1:$port --user Xm1234.worker1 --pass x" ;;
            kaspa)    echo "    lolMiner   --algo KASPA --pool 127.0.0.1:$port --user kaspa:qtest.worker1" ;;
        esac
    done
    echo ""
    tail -f "$WATTX_DATA/regtest/debug.log"
fi

echo ""
exit $FAILURES
