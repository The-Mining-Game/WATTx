#!/usr/bin/env python3
"""
WATTx Block Explorer - Etherscan-like functionality
A comprehensive Flask-based block explorer for WATTx blockchain
"""

from flask import Flask, jsonify, render_template_string, request, redirect
from flask_cors import CORS
import subprocess
import json
import os
import time
from functools import lru_cache

app = Flask(__name__)
CORS(app)

# Configuration
WATTX_CLI = "/home/nuts/Documents/WATTx/build/bin/wattx-cli"
DATADIR = "/home/nuts/.wattx_testnet"
RPC_USER = "wattx"
RPC_PASS = "wattxtest123"

# Cache for expensive operations
CACHE_TIMEOUT = 5  # seconds

def wattx_rpc(method, *params):
    """Execute WATTx RPC command"""
    cmd = [WATTX_CLI, f"-datadir={DATADIR}", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}"]
    cmd.append(method)
    for p in params:
        if isinstance(p, dict) or isinstance(p, list):
            cmd.append(json.dumps(p))
        else:
            cmd.append(str(p))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return result.stdout.strip()
        else:
            return {"error": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}

def format_wattx(satoshis):
    """Format satoshis to WATTx"""
    if satoshis is None:
        return "0"
    return f"{satoshis / 100000000:.8f}"

def get_tx_receipt(txid):
    """Get transaction receipt with contract info"""
    return wattx_rpc('gettransactionreceipt', txid)

# ============================================================================
# SHARED CSS STYLES
# ============================================================================
SHARED_STYLES = '''
<style>
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --border-color: #30363d;
        --text-primary: #c9d1d9;
        --text-secondary: #8b949e;
        --text-muted: #6e7681;
        --accent-blue: #58a6ff;
        --accent-green: #3fb950;
        --accent-red: #f85149;
        --accent-yellow: #d29922;
        --accent-purple: #a371f7;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        font-size: 14px;
        line-height: 1.5;
    }

    a { color: var(--accent-blue); text-decoration: none; }
    a:hover { text-decoration: underline; }

    .container { max-width: 1400px; margin: 0 auto; padding: 0 20px; }

    /* Navigation */
    .navbar {
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border-color);
        padding: 12px 0;
        position: sticky;
        top: 0;
        z-index: 100;
    }
    .navbar-content {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .logo {
        font-size: 20px;
        font-weight: 700;
        color: var(--accent-blue);
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .logo-icon {
        width: 32px;
        height: 32px;
        background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        color: white;
    }
    .nav-links { display: flex; gap: 24px; }
    .nav-links a { color: var(--text-secondary); font-size: 14px; }
    .nav-links a:hover { color: var(--text-primary); text-decoration: none; }

    /* Search */
    .search-container {
        background: linear-gradient(135deg, #1a365d 0%, #0d1117 100%);
        padding: 40px 0;
        border-bottom: 1px solid var(--border-color);
    }
    .search-title {
        text-align: center;
        margin-bottom: 20px;
    }
    .search-title h1 {
        font-size: 24px;
        margin-bottom: 8px;
    }
    .search-title p { color: var(--text-secondary); }
    .search-box {
        display: flex;
        max-width: 800px;
        margin: 0 auto;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
    }
    .search-select {
        background: var(--bg-tertiary);
        border: none;
        border-right: 1px solid var(--border-color);
        padding: 12px 16px;
        color: var(--text-primary);
        cursor: pointer;
    }
    .search-input {
        flex: 1;
        background: transparent;
        border: none;
        padding: 12px 16px;
        color: var(--text-primary);
        font-size: 14px;
    }
    .search-input:focus { outline: none; }
    .search-input::placeholder { color: var(--text-muted); }
    .search-btn {
        background: var(--accent-blue);
        border: none;
        padding: 12px 24px;
        color: white;
        cursor: pointer;
        font-weight: 600;
    }
    .search-btn:hover { background: #4c9aed; }

    /* Stats Grid */
    .stats-section { padding: 30px 0; }
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
    }
    .stat-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px;
    }
    .stat-card-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 12px;
    }
    .stat-icon {
        width: 40px;
        height: 40px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
    }
    .stat-icon.blue { background: rgba(88, 166, 255, 0.1); color: var(--accent-blue); }
    .stat-icon.green { background: rgba(63, 185, 80, 0.1); color: var(--accent-green); }
    .stat-icon.purple { background: rgba(163, 113, 247, 0.1); color: var(--accent-purple); }
    .stat-icon.yellow { background: rgba(210, 153, 34, 0.1); color: var(--accent-yellow); }
    .stat-label { color: var(--text-secondary); font-size: 12px; }
    .stat-value { font-size: 20px; font-weight: 600; }
    .stat-sub { color: var(--text-muted); font-size: 12px; margin-top: 4px; }

    /* Tables */
    .table-section { padding: 30px 0; }
    .table-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
    }
    @media (max-width: 1024px) {
        .table-grid { grid-template-columns: 1fr; }
    }
    .table-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
    }
    .table-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid var(--border-color);
    }
    .table-header h3 { font-size: 16px; }
    .table-header a { font-size: 13px; }
    .data-table { width: 100%; border-collapse: collapse; }
    .data-table th {
        text-align: left;
        padding: 12px 20px;
        color: var(--text-secondary);
        font-weight: 500;
        font-size: 12px;
        background: var(--bg-tertiary);
        border-bottom: 1px solid var(--border-color);
    }
    .data-table td {
        padding: 12px 20px;
        border-bottom: 1px solid var(--border-color);
        font-size: 13px;
    }
    .data-table tr:last-child td { border-bottom: none; }
    .data-table tr:hover { background: var(--bg-tertiary); }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 500;
    }
    .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
    .badge-pending { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
    .badge-failed { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
    .badge-contract { background: rgba(163, 113, 247, 0.15); color: var(--accent-purple); }
    .badge-in { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
    .badge-out { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }

    /* Hash/Address */
    .hash { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; }
    .hash-short { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; vertical-align: middle; }

    /* Detail Page */
    .page-header {
        padding: 24px 0;
        border-bottom: 1px solid var(--border-color);
    }
    .page-title {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .page-title h1 { font-size: 20px; }

    .detail-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        margin: 20px 0;
    }
    .detail-card-header {
        padding: 16px 20px;
        border-bottom: 1px solid var(--border-color);
        font-weight: 600;
    }
    .detail-row {
        display: flex;
        padding: 12px 20px;
        border-bottom: 1px solid var(--border-color);
    }
    .detail-row:last-child { border-bottom: none; }
    .detail-label {
        width: 200px;
        flex-shrink: 0;
        color: var(--text-secondary);
        font-size: 13px;
    }
    .detail-value {
        flex: 1;
        word-break: break-all;
    }

    /* Tabs */
    .tabs {
        display: flex;
        gap: 0;
        border-bottom: 1px solid var(--border-color);
        margin-top: 20px;
    }
    .tab {
        padding: 12px 20px;
        cursor: pointer;
        color: var(--text-secondary);
        border-bottom: 2px solid transparent;
        margin-bottom: -1px;
    }
    .tab:hover { color: var(--text-primary); }
    .tab.active {
        color: var(--accent-blue);
        border-bottom-color: var(--accent-blue);
    }
    .tab-content { display: none; padding: 20px 0; }
    .tab-content.active { display: block; }

    /* Code Box */
    .code-box {
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 16px;
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 12px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 400px;
        overflow-y: auto;
    }

    /* Buttons */
    .btn {
        display: inline-block;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        border: 1px solid var(--border-color);
        background: var(--bg-tertiary);
        color: var(--text-primary);
    }
    .btn:hover { background: var(--border-color); text-decoration: none; }
    .btn-primary {
        background: var(--accent-blue);
        border-color: var(--accent-blue);
        color: white;
    }
    .btn-primary:hover { background: #4c9aed; }

    /* Contract Read */
    .function-card {
        border: 1px solid var(--border-color);
        border-radius: 8px;
        margin-bottom: 12px;
        overflow: hidden;
    }
    .function-header {
        background: var(--bg-tertiary);
        padding: 12px 16px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .function-header:hover { background: var(--border-color); }
    .function-name { font-family: monospace; font-weight: 500; }
    .function-body {
        padding: 16px;
        display: none;
        border-top: 1px solid var(--border-color);
    }
    .function-body.open { display: block; }
    .function-input {
        width: 100%;
        padding: 8px 12px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        color: var(--text-primary);
        font-family: monospace;
        margin-top: 8px;
    }
    .function-result {
        margin-top: 12px;
        padding: 12px;
        background: var(--bg-primary);
        border-radius: 4px;
        font-family: monospace;
        font-size: 12px;
    }

    /* Footer */
    .footer {
        background: var(--bg-secondary);
        border-top: 1px solid var(--border-color);
        padding: 30px 0;
        margin-top: 40px;
        color: var(--text-secondary);
        font-size: 13px;
    }
    .footer-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Token */
    .token-icon {
        width: 24px;
        height: 24px;
        border-radius: 50%;
        background: var(--bg-tertiary);
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 10px;
        margin-right: 8px;
    }

    /* Loading */
    .loading {
        text-align: center;
        padding: 40px;
        color: var(--text-muted);
    }
    .spinner {
        border: 2px solid var(--border-color);
        border-top-color: var(--accent-blue);
        border-radius: 50%;
        width: 24px;
        height: 24px;
        animation: spin 1s linear infinite;
        margin: 0 auto 12px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Alerts */
    .alert {
        padding: 12px 16px;
        border-radius: 6px;
        margin: 16px 0;
    }
    .alert-info {
        background: rgba(88, 166, 255, 0.1);
        border: 1px solid rgba(88, 166, 255, 0.3);
        color: var(--accent-blue);
    }
    .alert-warning {
        background: rgba(210, 153, 34, 0.1);
        border: 1px solid rgba(210, 153, 34, 0.3);
        color: var(--accent-yellow);
    }

    /* Copy button */
    .copy-btn {
        background: transparent;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        padding: 4px 8px;
        font-size: 12px;
    }
    .copy-btn:hover { color: var(--text-primary); }
</style>
'''

# ============================================================================
# NAVIGATION BAR
# ============================================================================
NAVBAR = '''
<nav class="navbar">
    <div class="container navbar-content">
        <a href="/" class="logo">
            <div class="logo-icon">W</div>
            WATTx Explorer
        </a>
        <div class="nav-links">
            <a href="/">Home</a>
            <a href="/blocks">Blocks</a>
            <a href="/txs">Transactions</a>
            <a href="/contracts">Contracts</a>
            <a href="/tokens">Tokens</a>
        </div>
    </div>
</nav>
'''

# ============================================================================
# FOOTER
# ============================================================================
FOOTER = '''
<footer class="footer">
    <div class="container footer-content">
        <div>WATTx Testnet Explorer - Powered by WATTx Blockchain</div>
        <div>Block Height: <span id="footer-height">-</span></div>
    </div>
</footer>
<script>
    fetch('/api/info').then(r => r.json()).then(d => {
        document.getElementById('footer-height').textContent = d.blocks?.toLocaleString() || '-';
    });
</script>
'''

# ============================================================================
# HOME PAGE
# ============================================================================
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WATTx Explorer - Blockchain Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="search-container">
        <div class="container">
            <div class="search-title">
                <h1>WATTx Testnet Blockchain Explorer</h1>
                <p>Search for blocks, transactions, addresses, and contracts</p>
            </div>
            <form class="search-box" onsubmit="return handleSearch(event)">
                <select class="search-select" id="searchType">
                    <option value="all">All Filters</option>
                    <option value="address">Addresses</option>
                    <option value="tx">Txn Hash</option>
                    <option value="block">Block</option>
                    <option value="contract">Contract</option>
                </select>
                <input type="text" class="search-input" id="searchInput"
                       placeholder="Search by Address / Txn Hash / Block / Contract">
                <button type="submit" class="search-btn">Search</button>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="stats-section">
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card">
                    <div class="stat-card-header">
                        <div class="stat-icon blue">&#9632;</div>
                        <div>
                            <div class="stat-label">TOTAL BLOCKS</div>
                            <div class="stat-value" id="totalBlocks">-</div>
                        </div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <div class="stat-icon green">&#8644;</div>
                        <div>
                            <div class="stat-label">TRANSACTIONS</div>
                            <div class="stat-value" id="totalTxs">-</div>
                            <div class="stat-sub" id="tps">-</div>
                        </div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <div class="stat-icon purple">&#9670;</div>
                        <div>
                            <div class="stat-label">DIFFICULTY</div>
                            <div class="stat-value" id="difficulty">-</div>
                        </div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <div class="stat-icon yellow">&#9733;</div>
                        <div>
                            <div class="stat-label">TOTAL SUPPLY</div>
                            <div class="stat-value" id="supply">-</div>
                            <div class="stat-sub">WATTx</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-section">
            <div class="table-grid">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Latest Blocks</h3>
                        <a href="/blocks">View all blocks &rarr;</a>
                    </div>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Block</th>
                                <th>Age</th>
                                <th>Txns</th>
                                <th>Validator</th>
                            </tr>
                        </thead>
                        <tbody id="latestBlocks">
                            <tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="table-card">
                    <div class="table-header">
                        <h3>Latest Transactions</h3>
                        <a href="/txs">View all transactions &rarr;</a>
                    </div>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Txn Hash</th>
                                <th>Block</th>
                                <th>From/To</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody id="latestTxs">
                            <tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        function handleSearch(e) {
            e.preventDefault();
            const query = document.getElementById('searchInput').value.trim();
            const type = document.getElementById('searchType').value;

            if (!query) return false;

            // Determine type automatically
            if (query.length === 64) {
                // Could be tx hash or block hash
                window.location.href = '/tx/' + query;
            } else if (query.length === 40 && /^[0-9a-fA-F]+$/.test(query)) {
                window.location.href = '/address/' + query.toLowerCase();
            } else if (query.length === 34 && query.startsWith('q')) {
                // WATTx address
                window.location.href = '/address/' + query;
            } else if (!isNaN(query)) {
                window.location.href = '/block/' + query;
            } else {
                alert('Invalid search query');
            }
            return false;
        }

        function timeAgo(timestamp) {
            const seconds = Math.floor(Date.now() / 1000 - timestamp);
            if (seconds < 60) return seconds + ' secs ago';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' mins ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hrs ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }

        function truncate(str, len = 8) {
            if (!str) return '-';
            if (str.length <= len * 2) return str;
            return str.slice(0, len) + '...' + str.slice(-len);
        }

        async function loadStats() {
            const info = await fetch('/api/info').then(r => r.json());
            document.getElementById('totalBlocks').textContent = info.blocks?.toLocaleString() || '-';
            document.getElementById('difficulty').textContent = info.difficulty?.toExponential(2) || '-';
            document.getElementById('supply').textContent = (info.moneysupply || 0).toLocaleString();
        }

        async function loadBlocks() {
            const blocks = await fetch('/api/blocks/recent?limit=6').then(r => r.json());
            const tbody = document.getElementById('latestBlocks');

            if (!blocks.length) {
                tbody.innerHTML = '<tr><td colspan="4">No blocks found</td></tr>';
                return;
            }

            tbody.innerHTML = blocks.map(b => `
                <tr>
                    <td><a href="/block/${b.height}">${b.height}</a></td>
                    <td>${timeAgo(b.time)}</td>
                    <td><span class="badge badge-success">${b.tx_count} txns</span></td>
                    <td class="hash hash-short">${truncate(b.miner || 'PoS', 6)}</td>
                </tr>
            `).join('');
        }

        async function loadTxs() {
            const txs = await fetch('/api/txs/recent?limit=6').then(r => r.json());
            const tbody = document.getElementById('latestTxs');

            if (!txs.length) {
                tbody.innerHTML = '<tr><td colspan="4">No transactions found</td></tr>';
                return;
            }

            tbody.innerHTML = txs.map(tx => `
                <tr>
                    <td><a href="/tx/${tx.txid}" class="hash hash-short">${truncate(tx.txid)}</a></td>
                    <td><a href="/block/${tx.blockheight}">${tx.blockheight}</a></td>
                    <td>
                        ${tx.isContract ? '<span class="badge badge-contract">Contract</span>' : ''}
                        <span class="hash hash-short">${truncate(tx.from || '-', 6)}</span>
                    </td>
                    <td>${tx.value ? (tx.value / 1e8).toFixed(4) : '0'} WATTx</td>
                </tr>
            `).join('');
        }

        loadStats();
        loadBlocks();
        loadTxs();

        // Auto refresh
        setInterval(() => {
            loadStats();
            loadBlocks();
            loadTxs();
        }, 10000);
    </script>
</body>
</html>
'''

# ============================================================================
# BLOCKS LIST PAGE
# ============================================================================
BLOCKS_LIST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blocks - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Blocks</h1>
            </div>
        </div>

        <div class="detail-card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Block</th>
                        <th>Age</th>
                        <th>Txns</th>
                        <th>Size</th>
                        <th>Hash</th>
                    </tr>
                </thead>
                <tbody id="blocksList">
                    <tr><td colspan="5" class="loading"><div class="spinner"></div>Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div style="text-align: center; padding: 20px;">
            <button class="btn" onclick="loadMore()">Load More</button>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        let currentPage = 0;
        const pageSize = 25;

        function timeAgo(timestamp) {
            const seconds = Math.floor(Date.now() / 1000 - timestamp);
            if (seconds < 60) return seconds + ' secs ago';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' mins ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hrs ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }

        function truncate(str, len = 16) {
            if (!str) return '-';
            return str.slice(0, len) + '...' + str.slice(-8);
        }

        async function loadBlocks(append = false) {
            const blocks = await fetch(`/api/blocks?page=${currentPage}&limit=${pageSize}`).then(r => r.json());
            const tbody = document.getElementById('blocksList');

            const html = blocks.map(b => `
                <tr>
                    <td><a href="/block/${b.height}">${b.height}</a></td>
                    <td>${timeAgo(b.time)}</td>
                    <td>${b.tx_count}</td>
                    <td>${(b.size / 1024).toFixed(2)} KB</td>
                    <td><a href="/block/${b.hash}" class="hash">${truncate(b.hash)}</a></td>
                </tr>
            `).join('');

            if (append) {
                tbody.innerHTML += html;
            } else {
                tbody.innerHTML = html;
            }
        }

        function loadMore() {
            currentPage++;
            loadBlocks(true);
        }

        loadBlocks();
    </script>
</body>
</html>
'''

# ============================================================================
# BLOCK DETAIL PAGE
# ============================================================================
BLOCK_DETAIL_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Block {{ block_id }} - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Block <span id="blockNum">{{ block_id }}</span></h1>
            </div>
        </div>

        <div class="detail-card">
            <div class="detail-card-header">Overview</div>
            <div id="blockDetails">
                <div class="loading"><div class="spinner"></div>Loading...</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('txs')">Transactions</div>
        </div>

        <div id="txs-tab" class="tab-content active">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Txn Hash</th>
                        <th>Method</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody id="txsList">
                    <tr><td colspan="5" class="loading"><div class="spinner"></div>Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        const blockId = '{{ block_id }}';

        function truncate(str, len = 12) {
            if (!str) return '-';
            return str.slice(0, len) + '...' + str.slice(-6);
        }

        function formatTime(ts) {
            return new Date(ts * 1000).toLocaleString();
        }

        async function loadBlock() {
            const block = await fetch('/api/block/' + blockId).then(r => r.json());

            if (block.error) {
                document.getElementById('blockDetails').innerHTML = `<div class="alert alert-warning">${block.error}</div>`;
                return;
            }

            document.getElementById('blockNum').textContent = block.height;

            document.getElementById('blockDetails').innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Block Height:</div>
                    <div class="detail-value">${block.height}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Timestamp:</div>
                    <div class="detail-value">${formatTime(block.time)}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Transactions:</div>
                    <div class="detail-value">${block.tx?.length || 0} transactions</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Size:</div>
                    <div class="detail-value">${block.size?.toLocaleString()} bytes</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Difficulty:</div>
                    <div class="detail-value">${block.difficulty}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Hash:</div>
                    <div class="detail-value hash">${block.hash}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Parent Hash:</div>
                    <div class="detail-value"><a href="/block/${block.previousblockhash}" class="hash">${block.previousblockhash || '-'}</a></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Merkle Root:</div>
                    <div class="detail-value hash">${block.merkleroot}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">State Root:</div>
                    <div class="detail-value hash">${block.hashStateRoot || '-'}</div>
                </div>
            `;

            // Load transactions
            if (block.tx && block.tx.length > 0) {
                const txPromises = block.tx.slice(0, 50).map(txid =>
                    fetch('/api/tx/' + txid).then(r => r.json())
                );
                const txs = await Promise.all(txPromises);

                document.getElementById('txsList').innerHTML = txs.map(tx => {
                    let from = '-', to = '-', value = 0, method = 'Transfer';

                    if (tx.vin && tx.vin[0]) {
                        from = tx.vin[0].address || tx.vin[0].coinbase ? 'Coinbase' : '-';
                    }
                    if (tx.vout && tx.vout[0]) {
                        const vout = tx.vout[0];
                        if (vout.scriptPubKey) {
                            if (vout.scriptPubKey.type === 'call_sender') {
                                method = 'Contract Call';
                                to = 'Contract';
                            } else {
                                to = vout.scriptPubKey.address || '-';
                            }
                        }
                        value = vout.value || 0;
                    }

                    return `
                        <tr>
                            <td><a href="/tx/${tx.txid}" class="hash">${truncate(tx.txid)}</a></td>
                            <td><span class="badge ${method === 'Contract Call' ? 'badge-contract' : 'badge-success'}">${method}</span></td>
                            <td class="hash">${truncate(from, 8)}</td>
                            <td class="hash">${truncate(to, 8)}</td>
                            <td>${value.toFixed(4)} WATTx</td>
                        </tr>
                    `;
                }).join('');
            } else {
                document.getElementById('txsList').innerHTML = '<tr><td colspan="5">No transactions</td></tr>';
            }
        }

        loadBlock();
    </script>
</body>
</html>
'''

# ============================================================================
# TRANSACTION DETAIL PAGE
# ============================================================================
TX_DETAIL_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transaction {{ txid[:16] }}... - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Transaction Details</h1>
            </div>
        </div>

        <div class="detail-card">
            <div class="detail-card-header">Overview</div>
            <div id="txDetails">
                <div class="loading"><div class="spinner"></div>Loading...</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('overview')">Overview</div>
            <div class="tab" onclick="showTab('logs')">Logs</div>
            <div class="tab" onclick="showTab('raw')">Raw Data</div>
        </div>

        <div id="overview-tab" class="tab-content active">
            <div id="inputData"></div>
        </div>

        <div id="logs-tab" class="tab-content">
            <div id="eventLogs">No logs</div>
        </div>

        <div id="raw-tab" class="tab-content">
            <div class="code-box" id="rawData">Loading...</div>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        const txid = '{{ txid }}';

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab + '-tab').classList.add('active');
        }

        function truncate(str, len = 16) {
            if (!str) return '-';
            return str.slice(0, len) + '...';
        }

        function formatTime(ts) {
            return new Date(ts * 1000).toLocaleString();
        }

        async function loadTx() {
            const tx = await fetch('/api/tx/' + txid).then(r => r.json());

            if (tx.error) {
                document.getElementById('txDetails').innerHTML = `<div class="alert alert-warning">${tx.error}</div>`;
                return;
            }

            let status = tx.confirmations > 0 ? 'Success' : 'Pending';
            let statusClass = tx.confirmations > 0 ? 'badge-success' : 'badge-pending';

            // Extract from/to/value
            let from = '-', to = '-', value = 0, contractAddr = null, inputData = '';

            if (tx.vout) {
                for (const vout of tx.vout) {
                    if (vout.scriptPubKey) {
                        if (vout.scriptPubKey.type === 'call_sender') {
                            const asm = vout.scriptPubKey.asm || '';
                            const parts = asm.split(' ');
                            const callIdx = parts.indexOf('OP_CALL');
                            if (callIdx > 0) {
                                contractAddr = parts[callIdx - 1];
                            }
                            // Find input data
                            for (let i = 0; i < parts.length; i++) {
                                if (parts[i].length > 20 && /^[0-9a-f]+$/i.test(parts[i])) {
                                    inputData = parts[i];
                                    break;
                                }
                            }
                        } else if (vout.scriptPubKey.address) {
                            to = vout.scriptPubKey.address;
                            value += vout.value || 0;
                        }
                    }
                }
            }

            document.getElementById('txDetails').innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Transaction Hash:</div>
                    <div class="detail-value hash">${tx.txid} <button class="copy-btn" onclick="navigator.clipboard.writeText('${tx.txid}')">Copy</button></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Status:</div>
                    <div class="detail-value"><span class="badge ${statusClass}">${status}</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Block:</div>
                    <div class="detail-value"><a href="/block/${tx.blockhash}">${tx.blockhash ? truncate(tx.blockhash) : 'Pending'}</a></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Confirmations:</div>
                    <div class="detail-value">${tx.confirmations || 0}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Timestamp:</div>
                    <div class="detail-value">${tx.time ? formatTime(tx.time) : '-'}</div>
                </div>
                ${contractAddr ? `
                <div class="detail-row">
                    <div class="detail-label">Interacted With:</div>
                    <div class="detail-value"><a href="/address/${contractAddr}" class="hash"><span class="badge badge-contract">Contract</span> ${contractAddr}</a></div>
                </div>
                ` : ''}
                <div class="detail-row">
                    <div class="detail-label">Value:</div>
                    <div class="detail-value">${value.toFixed(8)} WATTx</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Size:</div>
                    <div class="detail-value">${tx.size} bytes</div>
                </div>
            `;

            if (inputData) {
                const selector = inputData.slice(0, 8);
                document.getElementById('inputData').innerHTML = `
                    <div class="detail-card">
                        <div class="detail-card-header">Input Data</div>
                        <div style="padding: 16px;">
                            <div style="margin-bottom: 8px;">
                                <span class="badge badge-contract">Method ID: ${selector}</span>
                            </div>
                            <div class="code-box">${inputData}</div>
                        </div>
                    </div>
                `;
            }

            document.getElementById('rawData').textContent = JSON.stringify(tx, null, 2);

            // Load receipt for logs
            if (contractAddr) {
                const receipt = await fetch('/api/tx/' + txid + '/receipt').then(r => r.json());
                if (receipt && receipt.length > 0 && receipt[0].log) {
                    const logs = receipt[0].log;
                    if (logs.length > 0) {
                        document.getElementById('eventLogs').innerHTML = logs.map((log, i) => `
                            <div class="detail-card">
                                <div class="detail-card-header">Log [${i}]</div>
                                <div class="detail-row">
                                    <div class="detail-label">Address:</div>
                                    <div class="detail-value"><a href="/address/${log.address}">${log.address}</a></div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Topics:</div>
                                    <div class="detail-value code-box">${log.topics?.join('\\n') || '-'}</div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Data:</div>
                                    <div class="detail-value code-box">${log.data || '-'}</div>
                                </div>
                            </div>
                        `).join('');
                    }
                }
            }
        }

        loadTx();
    </script>
</body>
</html>
'''

# ============================================================================
# ADDRESS/CONTRACT PAGE
# ============================================================================
ADDRESS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Address {{ address }} - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <span id="addrType" class="badge badge-success">Address</span>
                <h1 class="hash" style="margin-left: 12px;">{{ address }}</h1>
            </div>
        </div>

        <div class="stats-grid" style="margin: 20px 0;">
            <div class="stat-card">
                <div class="stat-label">BALANCE</div>
                <div class="stat-value" id="balance">-</div>
                <div class="stat-sub">WATTx</div>
            </div>
            <div class="stat-card" id="codeCard" style="display: none;">
                <div class="stat-label">CODE SIZE</div>
                <div class="stat-value" id="codeSize">-</div>
                <div class="stat-sub">bytes</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('txs')">Transactions</div>
            <div class="tab" id="codeTab" style="display: none;" onclick="showTab('code')">Contract</div>
            <div class="tab" id="readTab" style="display: none;" onclick="showTab('read')">Read Contract</div>
        </div>

        <div id="txs-tab" class="tab-content active">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Txn Hash</th>
                        <th>Block</th>
                        <th>Age</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody id="txsList">
                    <tr><td colspan="6" class="loading"><div class="spinner"></div>Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div id="code-tab" class="tab-content">
            <div class="detail-card">
                <div class="detail-card-header">Contract Bytecode</div>
                <div class="code-box" id="bytecode">Loading...</div>
            </div>
        </div>

        <div id="read-tab" class="tab-content">
            <div class="alert alert-info">Read contract state - call view functions without gas</div>
            <div id="readFunctions"></div>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        const address = '{{ address }}';
        let isContract = false;

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab + '-tab').classList.add('active');
        }

        function truncate(str, len = 12) {
            if (!str) return '-';
            return str.slice(0, len) + '...' + str.slice(-6);
        }

        function timeAgo(timestamp) {
            const seconds = Math.floor(Date.now() / 1000 - timestamp);
            if (seconds < 60) return seconds + ' secs ago';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' mins ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hrs ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }

        async function callFunction(selector, resultId) {
            document.getElementById(resultId).textContent = 'Calling...';
            try {
                const res = await fetch('/api/contract/' + address + '/call/' + selector).then(r => r.json());
                if (res.executionResult) {
                    const output = res.executionResult.output;
                    let decoded = output;
                    if (output && output.length === 64) {
                        // Try to decode as address or number
                        if (output.startsWith('000000000000000000000000')) {
                            decoded = '0x' + output.slice(24) + ' (address)';
                        } else {
                            try {
                                const num = BigInt('0x' + output);
                                decoded = output + '\\n= ' + (Number(num) / 1e18).toFixed(6) + ' (18 decimals)';
                            } catch(e) {}
                        }
                    }
                    document.getElementById(resultId).textContent =
                        'Status: ' + (res.executionResult.excepted || 'None') + '\\n' +
                        'Gas Used: ' + res.executionResult.gasUsed + '\\n\\n' +
                        'Output:\\n' + decoded;
                } else {
                    document.getElementById(resultId).textContent = JSON.stringify(res, null, 2);
                }
            } catch(e) {
                document.getElementById(resultId).textContent = 'Error: ' + e.message;
            }
        }

        async function loadAddress() {
            // Check if it's a contract
            const contractData = await fetch('/api/contract/' + address).then(r => r.json());

            if (contractData.code && contractData.code.length > 2) {
                isContract = true;
                document.getElementById('addrType').textContent = 'Contract';
                document.getElementById('addrType').className = 'badge badge-contract';
                document.getElementById('codeCard').style.display = 'block';
                document.getElementById('codeTab').style.display = 'block';
                document.getElementById('readTab').style.display = 'block';
                document.getElementById('codeSize').textContent = (contractData.code.length / 2).toLocaleString();
                document.getElementById('bytecode').textContent = contractData.code;
                document.getElementById('balance').textContent = contractData.accountInfo?.balance || '0';

                // Add common read functions
                const functions = [
                    { name: 'token0()', selector: '0dfe1681' },
                    { name: 'token1()', selector: 'd21220a7' },
                    { name: 'reserve0()', selector: '443cb4bc' },
                    { name: 'reserve1()', selector: '5a76f25e' },
                    { name: 'totalLP()', selector: '132c4feb' },
                    { name: 'totalSupply()', selector: '18160ddd' },
                    { name: 'name()', selector: '06fdde03' },
                    { name: 'symbol()', selector: '95d89b41' },
                    { name: 'decimals()', selector: '313ce567' },
                    { name: 'owner()', selector: '8da5cb5b' },
                ];

                document.getElementById('readFunctions').innerHTML = functions.map((f, i) => `
                    <div class="function-card">
                        <div class="function-header" onclick="this.nextElementSibling.classList.toggle('open')">
                            <span class="function-name">${f.name}</span>
                            <span>&#9660;</span>
                        </div>
                        <div class="function-body">
                            <button class="btn btn-primary" onclick="callFunction('${f.selector}', 'result-${i}')">Query</button>
                            <div class="function-result" id="result-${i}">Click Query to get result</div>
                        </div>
                    </div>
                `).join('');
            } else {
                // Regular address - get balance
                document.getElementById('balance').textContent = '0';
            }

            // Load transactions (search logs for this address)
            const logs = await fetch('/api/address/' + address + '/txs').then(r => r.json());
            const tbody = document.getElementById('txsList');

            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6">No transactions found</td></tr>';
                return;
            }

            tbody.innerHTML = logs.map(tx => `
                <tr>
                    <td><a href="/tx/${tx.transactionHash}" class="hash">${truncate(tx.transactionHash)}</a></td>
                    <td><a href="/block/${tx.blockNumber}">${tx.blockNumber}</a></td>
                    <td>${tx.blockTime ? timeAgo(tx.blockTime) : '-'}</td>
                    <td class="hash">${truncate(tx.from || '-', 8)}</td>
                    <td class="hash">${truncate(tx.to || '-', 8)}</td>
                    <td>-</td>
                </tr>
            `).join('');
        }

        loadAddress();
    </script>
</body>
</html>
'''

# ============================================================================
# TRANSACTIONS LIST PAGE
# ============================================================================
TXS_LIST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transactions - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Transactions</h1>
            </div>
        </div>

        <div class="detail-card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Txn Hash</th>
                        <th>Block</th>
                        <th>Age</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody id="txsList">
                    <tr><td colspan="6" class="loading"><div class="spinner"></div>Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div style="text-align: center; padding: 20px;">
            <button class="btn" onclick="loadMore()">Load More</button>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        let currentPage = 0;

        function truncate(str, len = 12) {
            if (!str) return '-';
            return str.slice(0, len) + '...' + str.slice(-6);
        }

        function timeAgo(timestamp) {
            const seconds = Math.floor(Date.now() / 1000 - timestamp);
            if (seconds < 60) return seconds + ' secs ago';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' mins ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hrs ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }

        async function loadTxs(append = false) {
            const txs = await fetch(`/api/txs?page=${currentPage}&limit=25`).then(r => r.json());
            const tbody = document.getElementById('txsList');

            const html = txs.map(tx => `
                <tr>
                    <td><a href="/tx/${tx.txid}" class="hash">${truncate(tx.txid)}</a></td>
                    <td><a href="/block/${tx.blockheight}">${tx.blockheight}</a></td>
                    <td>${tx.time ? timeAgo(tx.time) : '-'}</td>
                    <td class="hash">${truncate(tx.from || '-', 8)}</td>
                    <td>${tx.isContract ? '<span class="badge badge-contract">Contract</span>' : ''} <span class="hash">${truncate(tx.to || '-', 8)}</span></td>
                    <td>${tx.value ? (tx.value / 1e8).toFixed(4) : '0'} WATTx</td>
                </tr>
            `).join('');

            if (append) {
                tbody.innerHTML += html;
            } else {
                tbody.innerHTML = html;
            }
        }

        function loadMore() {
            currentPage++;
            loadTxs(true);
        }

        loadTxs();
    </script>
</body>
</html>
'''

# ============================================================================
# TOKENS LIST PAGE
# ============================================================================
TOKENS_LIST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tokens - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Token Tracker</h1>
            </div>
        </div>

        <div class="alert alert-info">
            Showing known token contracts deployed on WATTx Testnet
        </div>

        <div class="detail-card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Token</th>
                        <th>Contract Address</th>
                        <th>Total Supply</th>
                    </tr>
                </thead>
                <tbody id="tokensList">
                    <tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    ''' + FOOTER + '''

    <script>
        // Known tokens
        const knownTokens = [
            { address: 'a33aa33adedc976e4cb2c7f5f136e11c25387168', name: 'Token A', symbol: 'TKA' },
            { address: '19910a5e56164e72dd59a111246169307ca40a62', name: 'Token B', symbol: 'TKB' },
        ];

        async function loadTokens() {
            const tbody = document.getElementById('tokensList');
            let html = '';

            for (let i = 0; i < knownTokens.length; i++) {
                const token = knownTokens[i];
                let supply = '-';

                try {
                    const res = await fetch('/api/contract/' + token.address + '/call/18160ddd').then(r => r.json());
                    if (res.executionResult && res.executionResult.output) {
                        const num = BigInt('0x' + res.executionResult.output);
                        supply = (Number(num) / 1e18).toLocaleString();
                    }
                } catch(e) {}

                html += `
                    <tr>
                        <td>${i + 1}</td>
                        <td>
                            <div class="token-icon">${token.symbol.slice(0, 2)}</div>
                            <strong>${token.name}</strong> (${token.symbol})
                        </td>
                        <td><a href="/address/${token.address}" class="hash">${token.address}</a></td>
                        <td>${supply}</td>
                    </tr>
                `;
            }

            tbody.innerHTML = html || '<tr><td colspan="4">No tokens found</td></tr>';
        }

        loadTokens();
    </script>
</body>
</html>
'''

# ============================================================================
# CONTRACTS LIST PAGE
# ============================================================================
CONTRACTS_LIST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contracts - WATTx Explorer</title>
    ''' + SHARED_STYLES + '''
</head>
<body>
    ''' + NAVBAR + '''

    <div class="container">
        <div class="page-header">
            <div class="page-title">
                <h1>Smart Contracts</h1>
            </div>
        </div>

        <div class="alert alert-info">
            Showing known smart contracts deployed on WATTx Testnet
        </div>

        <div class="detail-card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Contract</th>
                        <th>Address</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody id="contractsList">
                    <tr>
                        <td><strong>WATTx DEX</strong></td>
                        <td><a href="/address/20a1d206b61870382f941e61c19c69dd19fbef50" class="hash">20a1d206b61870382f941e61c19c69dd19fbef50</a></td>
                        <td><span class="badge badge-contract">DEX / AMM</span></td>
                    </tr>
                    <tr>
                        <td><strong>Token A</strong></td>
                        <td><a href="/address/a33aa33adedc976e4cb2c7f5f136e11c25387168" class="hash">a33aa33adedc976e4cb2c7f5f136e11c25387168</a></td>
                        <td><span class="badge badge-success">ERC20</span></td>
                    </tr>
                    <tr>
                        <td><strong>Token B</strong></td>
                        <td><a href="/address/19910a5e56164e72dd59a111246169307ca40a62" class="hash">19910a5e56164e72dd59a111246169307ca40a62</a></td>
                        <td><span class="badge badge-success">ERC20</span></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    ''' + FOOTER + '''
</body>
</html>
'''

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/info')
def api_info():
    return jsonify(wattx_rpc('getblockchaininfo'))

@app.route('/api/blocks/recent')
def api_recent_blocks():
    limit = min(int(request.args.get('limit', 10)), 50)
    info = wattx_rpc('getblockchaininfo')
    if isinstance(info, dict) and 'error' in info:
        return jsonify([])

    height = info.get('blocks', 0)
    blocks = []

    for h in range(height, max(0, height - limit), -1):
        block_hash = wattx_rpc('getblockhash', h)
        if isinstance(block_hash, str) and len(block_hash) == 64:
            block = wattx_rpc('getblock', block_hash)
            if isinstance(block, dict):
                blocks.append({
                    'height': block.get('height'),
                    'hash': block.get('hash'),
                    'time': block.get('time'),
                    'tx_count': len(block.get('tx', [])),
                    'size': block.get('size', 0),
                    'miner': block.get('miner', '')
                })

    return jsonify(blocks)

@app.route('/api/blocks')
def api_blocks():
    page = int(request.args.get('page', 0))
    limit = min(int(request.args.get('limit', 25)), 100)

    info = wattx_rpc('getblockchaininfo')
    if isinstance(info, dict) and 'error' in info:
        return jsonify([])

    height = info.get('blocks', 0)
    start = height - (page * limit)
    blocks = []

    for h in range(start, max(0, start - limit), -1):
        block_hash = wattx_rpc('getblockhash', h)
        if isinstance(block_hash, str) and len(block_hash) == 64:
            block = wattx_rpc('getblock', block_hash)
            if isinstance(block, dict):
                blocks.append({
                    'height': block.get('height'),
                    'hash': block.get('hash'),
                    'time': block.get('time'),
                    'tx_count': len(block.get('tx', [])),
                    'size': block.get('size', 0)
                })

    return jsonify(blocks)

@app.route('/api/block/<block_id>')
def api_block(block_id):
    if block_id.isdigit():
        block_hash = wattx_rpc('getblockhash', int(block_id))
        if isinstance(block_hash, dict) and 'error' in block_hash:
            return jsonify(block_hash)
    else:
        block_hash = block_id

    return jsonify(wattx_rpc('getblock', block_hash))

@app.route('/api/tx/<txid>')
def api_tx(txid):
    return jsonify(wattx_rpc('getrawtransaction', txid, True))

@app.route('/api/tx/<txid>/receipt')
def api_tx_receipt(txid):
    return jsonify(wattx_rpc('gettransactionreceipt', txid))

@app.route('/api/txs/recent')
def api_recent_txs():
    limit = min(int(request.args.get('limit', 10)), 50)
    info = wattx_rpc('getblockchaininfo')
    if isinstance(info, dict) and 'error' in info:
        return jsonify([])

    height = info.get('blocks', 0)
    txs = []

    for h in range(height, max(0, height - 20), -1):
        if len(txs) >= limit:
            break
        block_hash = wattx_rpc('getblockhash', h)
        if isinstance(block_hash, str) and len(block_hash) == 64:
            block = wattx_rpc('getblock', block_hash)
            if isinstance(block, dict):
                for txid in block.get('tx', []):
                    if len(txs) >= limit:
                        break
                    tx = wattx_rpc('getrawtransaction', txid, True)
                    if isinstance(tx, dict):
                        is_contract = False
                        from_addr = ''
                        to_addr = ''
                        value = 0

                        if tx.get('vout'):
                            for vout in tx['vout']:
                                sp = vout.get('scriptPubKey', {})
                                if sp.get('type') == 'call_sender':
                                    is_contract = True
                                elif sp.get('address'):
                                    to_addr = sp['address']
                                    value += vout.get('value', 0) * 1e8

                        txs.append({
                            'txid': txid,
                            'blockheight': h,
                            'time': block.get('time'),
                            'isContract': is_contract,
                            'from': from_addr,
                            'to': to_addr,
                            'value': value
                        })

    return jsonify(txs)

@app.route('/api/txs')
def api_txs():
    page = int(request.args.get('page', 0))
    limit = min(int(request.args.get('limit', 25)), 100)

    info = wattx_rpc('getblockchaininfo')
    if isinstance(info, dict) and 'error' in info:
        return jsonify([])

    height = info.get('blocks', 0)
    start = height - (page * 5)  # Approximate
    txs = []

    for h in range(start, max(0, start - 50), -1):
        if len(txs) >= limit:
            break
        block_hash = wattx_rpc('getblockhash', h)
        if isinstance(block_hash, str) and len(block_hash) == 64:
            block = wattx_rpc('getblock', block_hash)
            if isinstance(block, dict):
                for txid in block.get('tx', []):
                    if len(txs) >= limit:
                        break
                    tx = wattx_rpc('getrawtransaction', txid, True)
                    if isinstance(tx, dict):
                        is_contract = False
                        to_addr = ''
                        value = 0

                        if tx.get('vout'):
                            for vout in tx['vout']:
                                sp = vout.get('scriptPubKey', {})
                                if sp.get('type') == 'call_sender':
                                    is_contract = True
                                elif sp.get('address'):
                                    to_addr = sp['address']
                                    value += vout.get('value', 0) * 1e8

                        txs.append({
                            'txid': txid,
                            'blockheight': h,
                            'time': block.get('time'),
                            'isContract': is_contract,
                            'to': to_addr,
                            'value': value
                        })

    return jsonify(txs)

@app.route('/api/contract/<address>')
def api_contract(address):
    code = wattx_rpc('getcontractcode', address)
    account_info = wattx_rpc('getaccountinfo', address)

    return jsonify({
        'address': address,
        'code': code if isinstance(code, str) else None,
        'codeSize': len(code) // 2 if isinstance(code, str) else 0,
        'accountInfo': account_info if isinstance(account_info, dict) else {}
    })

@app.route('/api/contract/<address>/call/<data>')
def api_contract_call(address, data):
    result = wattx_rpc('callcontract', address, data)
    return jsonify(result)

@app.route('/api/address/<address>/txs')
def api_address_txs(address):
    # Search for transactions involving this address
    logs = wattx_rpc('searchlogs', 0, -1, {"addresses": [address]})
    if isinstance(logs, list):
        return jsonify(logs[:50])
    return jsonify([])

@app.route('/api/validators/stats')
def api_validators_stats():
    """Get validator statistics for WATTx PoS"""
    info = wattx_rpc('getblockchaininfo')
    staking_info = wattx_rpc('getstakinginfo')

    # Calculate stats from blockchain info
    blocks = info.get('blocks', 0) if isinstance(info, dict) else 0
    difficulty = info.get('difficulty', 0) if isinstance(info, dict) else 0

    # Get staking details
    staking = staking_info.get('staking', False) if isinstance(staking_info, dict) else False
    weight = staking_info.get('weight', 0) if isinstance(staking_info, dict) else 0
    netstakeweight = staking_info.get('netstakeweight', 0) if isinstance(staking_info, dict) else 0

    return jsonify({
        'totalValidators': 1,  # Testnet has 1 active validator
        'activeValidators': 1 if staking else 0,
        'totalStaked': netstakeweight / 1e8 if netstakeweight else 0,
        'networkWeight': netstakeweight / 1e8 if netstakeweight else 0,
        'difficulty': difficulty,
        'blocks': blocks,
        'staking': staking
    })

@app.route('/api/search')
def api_search():
    """Search for blocks, transactions, or addresses"""
    query = request.args.get('q', '').strip()

    if not query:
        return jsonify({'type': 'none', 'result': None})

    # Check if it's a block number
    if query.isdigit():
        block_hash = wattx_rpc('getblockhash', int(query))
        if isinstance(block_hash, str) and len(block_hash) == 64:
            return jsonify({'type': 'block', 'result': int(query)})

    # Check if it's a transaction hash (64 hex chars)
    if len(query) == 64:
        tx = wattx_rpc('getrawtransaction', query, 1)
        if isinstance(tx, dict) and 'txid' in tx:
            return jsonify({'type': 'tx', 'result': query})
        # Could be a block hash
        block = wattx_rpc('getblock', query)
        if isinstance(block, dict) and 'hash' in block:
            return jsonify({'type': 'block', 'result': block.get('height')})

    # Check if it's a contract address (40 hex chars)
    if len(query) == 40:
        code = wattx_rpc('getcontractcode', query)
        if isinstance(code, str) and len(code) > 0:
            return jsonify({'type': 'contract', 'result': query})
        return jsonify({'type': 'address', 'result': query})

    # Check if it's a WATTx address (starts with q or W)
    if query.startswith('q') or query.startswith('W') or query.startswith('Q'):
        return jsonify({'type': 'address', 'result': query})

    return jsonify({'type': 'none', 'result': None})

# ============================================================================
# PAGE ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template_string(HOME_TEMPLATE)

@app.route('/blocks')
def blocks_list():
    return render_template_string(BLOCKS_LIST_TEMPLATE)

@app.route('/block/<block_id>')
def view_block(block_id):
    return render_template_string(BLOCK_DETAIL_TEMPLATE, block_id=block_id)

@app.route('/tx/<txid>')
def view_tx(txid):
    return render_template_string(TX_DETAIL_TEMPLATE, txid=txid)

@app.route('/txs')
def txs_list():
    return render_template_string(TXS_LIST_TEMPLATE)

@app.route('/address/<address>')
def view_address(address):
    return render_template_string(ADDRESS_TEMPLATE, address=address)

@app.route('/contract/<address>')
def view_contract(address):
    return redirect(f'/address/{address}')

@app.route('/tokens')
def tokens_list():
    return render_template_string(TOKENS_LIST_TEMPLATE)

@app.route('/contracts')
def contracts_list():
    return render_template_string(CONTRACTS_LIST_TEMPLATE)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("WATTx Block Explorer - Etherscan-like Interface")
    print("=" * 60)
    print("Starting on http://localhost:5000")
    print("")
    print("Pages:")
    print("  - Home:         http://localhost:5000/")
    print("  - Blocks:       http://localhost:5000/blocks")
    print("  - Transactions: http://localhost:5000/txs")
    print("  - Contracts:    http://localhost:5000/contracts")
    print("  - Tokens:       http://localhost:5000/tokens")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
