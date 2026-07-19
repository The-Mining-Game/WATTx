#!/usr/bin/env python3
"""
Mock daemon RPC servers for WATTx AuxPoW merged mining tests.

Starts one lightweight HTTP server per algorithm, each simulating the real
daemon's RPC/REST interface so the multi-merged stratum server can be tested
without live parent-chain nodes.

Usage:
    # Run all daemons (blocks until Ctrl-C)
    python3 mock_daemons.py

    # Run a specific algorithm only
    python3 mock_daemons.py --algo sha256d
    python3 mock_daemons.py --algo scrypt
    python3 mock_daemons.py --algo ethash
    python3 mock_daemons.py --algo equihash
    python3 mock_daemons.py --algo x11
    python3 mock_daemons.py --algo kaspa

Default ports (match each chain's mainnet RPC default):
    SHA256d  / Bitcoin   -> 8332
    Scrypt   / Litecoin  -> 9332
    Ethash   / ETC       -> 8545
    Equihash / Zcash     -> 8232
    X11      / Dash      -> 9998
    kHeavyHash / Kaspa   -> 16110  (REST, not JSON-RPC)
"""

import argparse
import hashlib
import http.server
import json
import os
import struct
import sys
import threading
import time
from urllib.parse import urlparse, parse_qs

# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def make_coinbase_tx(height: int, extra: bytes = b'\x00' * 64) -> bytes:
    """Build a minimal Bitcoin-style coinbase transaction."""
    height_bytes = height.to_bytes(3, 'little')
    script_sig = bytes([0x03]) + height_bytes + extra  # BIP34 height + reserve
    coinbase_input = (
        b'\x00' * 32 +           # prevout hash (null)
        b'\xff\xff\xff\xff' +    # prevout index (coinbase)
        encode_varint(len(script_sig)) + script_sig +
        b'\xff\xff\xff\xff'      # sequence
    )
    # Single OP_TRUE output (value=0)
    script_pubkey = bytes([0x51])  # OP_1 (anyone-can-spend for testing)
    coinbase_output = b'\x00' * 8 + encode_varint(len(script_pubkey)) + script_pubkey

    tx = (
        struct.pack('<I', 2) +         # version
        encode_varint(1) +             # 1 input
        coinbase_input +
        encode_varint(1) +             # 1 output
        coinbase_output +
        b'\x00\x00\x00\x00'           # locktime
    )
    return tx

def merkle_root(txids: list) -> bytes:
    if not txids:
        return b'\x00' * 32
    hashes = [bytes.fromhex(t) if isinstance(t, str) else t for t in txids]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [sha256d(hashes[i] + hashes[i+1]) for i in range(0, len(hashes), 2)]
    return hashes[0]

def bits_to_target(bits_hex: str) -> str:
    bits = int(bits_hex, 16)
    exponent = bits >> 24
    mantissa = bits & 0x007fffff
    target_int = mantissa * (2 ** (8 * (exponent - 3)))
    return format(target_int, '064x')


# ──────────────────────────────────────────────────────────────────────────────
# Base handler
# ──────────────────────────────────────────────────────────────────────────────

class BaseMockHandler(http.server.BaseHTTPRequestHandler):
    ALGO = "base"

    def log_message(self, fmt, *args):
        ts = time.strftime('%H:%M:%S')
        print(f"  [{ts}] [{self.ALGO.upper():10s}] {args[0]}", flush=True)

    def send_json(self, body: dict, status: int = 200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b'{}'
        try:
            return json.loads(raw)
        except Exception:
            return {}


# ──────────────────────────────────────────────────────────────────────────────
# SHA256d  —  Bitcoin Core JSON-RPC  (port 8332)
# ──────────────────────────────────────────────────────────────────────────────

class SHA256dState:
    def __init__(self):
        self.height   = 800000
        self.prevhash = 'a' * 64
        self.bits     = '1a0fffff'   # low difficulty for testing
        self.lock     = threading.Lock()
        self.submitted = []

    def get_block_template(self):
        with self.lock:
            coinbase_tx = make_coinbase_tx(self.height)
            coinbase_txid = sha256d(coinbase_tx)[::-1].hex()
            mroot = merkle_root([coinbase_txid])
            target = bits_to_target(self.bits)
            return {
                'version':           0x20000000,
                'previousblockhash': self.prevhash,
                'transactions':      [],
                'coinbaseaux':       {'flags': ''},
                'coinbasetxn': {
                    'data':    coinbase_tx.hex(),
                    'txid':    coinbase_txid,
                    'hash':    coinbase_txid,
                    'depends': [],
                    'fee':     0,
                    'sigops':  1,
                    'weight':  500,
                },
                'coinbasevalue':     312500000,
                'longpollid':        f'{self.prevhash}-0',
                'target':            target,
                'mintime':           int(time.time()) - 600,
                'mutable':           ['time', 'transactions', 'prevblock', 'coinbase/append'],
                'noncerange':        '00000000ffffffff',
                'sigoplimit':        20000,
                'sizelimit':         1000000,
                'weightlimit':       4000000,
                'curtime':           int(time.time()),
                'bits':              self.bits,
                'height':            self.height,
                'default_witness_commitment': '6a24aa21a9ed' + 'e' * 64,
            }

    def submit(self, blob: str):
        with self.lock:
            self.submitted.append({'blob': blob, 'height': self.height, 'ts': time.time()})
            self.prevhash = hashlib.sha256(bytes.fromhex(blob[:80*2])).hexdigest()
            self.height += 1
            print(f"  [SHA256d] Block accepted! New height: {self.height}")
            return None   # Bitcoin returns null on success


_sha256d_state = SHA256dState()

class SHA256dHandler(BaseMockHandler):
    ALGO = 'sha256d'

    def do_POST(self):
        req = self.read_body()
        method = req.get('method', '')
        rid    = req.get('id', 0)
        params = req.get('params', [])

        if method == 'getblocktemplate':
            self.send_json({'id': rid, 'result': _sha256d_state.get_block_template(), 'error': None})
        elif method == 'submitblock':
            blob = params[0] if params else ''
            result = _sha256d_state.submit(blob)
            self.send_json({'id': rid, 'result': result, 'error': None})
        elif method == 'getmininginfo':
            self.send_json({'id': rid, 'result': {
                'blocks': _sha256d_state.height, 'difficulty': 0.001,
                'networkhashps': 1e15, 'chain': 'main',
            }, 'error': None})
        elif method == 'getblockchaininfo':
            self.send_json({'id': rid, 'result': {
                'chain': 'main', 'blocks': _sha256d_state.height, 'headers': _sha256d_state.height,
            }, 'error': None})
        else:
            self.send_json({'id': rid, 'result': None,
                            'error': {'code': -32601, 'message': f'Method not found: {method}'}})


# ──────────────────────────────────────────────────────────────────────────────
# Scrypt  —  Litecoin JSON-RPC  (port 9332)
# ──────────────────────────────────────────────────────────────────────────────

class ScryptState:
    def __init__(self):
        self.height   = 2800000
        self.prevhash = 'b' * 64
        self.bits     = '1a0fffff'
        self.lock     = threading.Lock()
        self.submitted = []

    def get_block_template(self):
        with self.lock:
            coinbase_tx = make_coinbase_tx(self.height)
            coinbase_txid = sha256d(coinbase_tx)[::-1].hex()
            target = bits_to_target(self.bits)
            return {
                'version':           0x20000000,
                'previousblockhash': self.prevhash,
                'transactions':      [],
                'coinbasetxn': {
                    'data': coinbase_tx.hex(),
                    'txid': coinbase_txid,
                    'hash': coinbase_txid,
                    'depends': [], 'fee': 0, 'sigops': 1, 'weight': 500,
                },
                'coinbasevalue':     312500000,
                'target':            target,
                'mintime':           int(time.time()) - 600,
                'mutable':           ['time', 'transactions', 'prevblock', 'coinbase/append'],
                'noncerange':        '00000000ffffffff',
                'curtime':           int(time.time()),
                'bits':              self.bits,
                'height':            self.height,
            }

    def submit(self, blob: str):
        with self.lock:
            self.submitted.append({'blob': blob, 'height': self.height})
            self.height += 1
            print(f"  [SCRYPT ] Block accepted! New height: {self.height}")
            return None

_scrypt_state = ScryptState()

class ScryptHandler(BaseMockHandler):
    ALGO = 'scrypt'

    def do_POST(self):
        req = self.read_body()
        method = req.get('method', '')
        rid    = req.get('id', 0)
        params = req.get('params', [])

        if method == 'getblocktemplate':
            self.send_json({'id': rid, 'result': _scrypt_state.get_block_template(), 'error': None})
        elif method == 'submitblock':
            blob = params[0] if params else ''
            self.send_json({'id': rid, 'result': _scrypt_state.submit(blob), 'error': None})
        elif method in ('getmininginfo', 'getblockchaininfo'):
            self.send_json({'id': rid, 'result': {'blocks': _scrypt_state.height, 'chain': 'main'}, 'error': None})
        else:
            self.send_json({'id': rid, 'result': None,
                            'error': {'code': -32601, 'message': f'Method not found: {method}'}})


# ──────────────────────────────────────────────────────────────────────────────
# Ethash  —  Ethereum JSON-RPC  (port 8545)
# Uses eth_getWork / eth_submitWork / eth_blockNumber
# ──────────────────────────────────────────────────────────────────────────────

class EthashState:
    def __init__(self):
        self.block_number = 19000000
        self.lock = threading.Lock()
        self.submitted = []
        # Very easy target for testing (leading zeros)
        self.target = '0x' + '0' * 4 + 'f' * 60  # low difficulty

    def get_work(self):
        with self.lock:
            header_hash = '0x' + hashlib.sha256(
                f'ethash_header_{self.block_number}'.encode()).hexdigest()
            seed_hash   = '0x' + hashlib.sha256(
                f'ethash_seed_{self.block_number // 30000}'.encode()).hexdigest()
            return [header_hash, seed_hash, self.target]

    def submit_work(self, nonce, header_hash, mix_hash):
        with self.lock:
            self.submitted.append({'nonce': nonce, 'header': header_hash, 'mix': mix_hash})
            self.block_number += 1
            print(f"  [ETHASH ] Block accepted! New block: {hex(self.block_number)}")
            return True

    def block_num_hex(self):
        with self.lock:
            return hex(self.block_number)

_ethash_state = EthashState()

class EthashHandler(BaseMockHandler):
    ALGO = 'ethash'

    def do_POST(self):
        req = self.read_body()
        method = req.get('method', '')
        rid    = req.get('id', 0)
        params = req.get('params', [])

        if method == 'eth_getWork':
            self.send_json({'id': rid, 'result': _ethash_state.get_work(), 'error': None})
        elif method == 'eth_submitWork':
            nonce, header, mix = (params + ['', '', ''])[:3]
            self.send_json({'id': rid, 'result': _ethash_state.submit_work(nonce, header, mix), 'error': None})
        elif method == 'eth_blockNumber':
            self.send_json({'id': rid, 'result': _ethash_state.block_num_hex(), 'error': None})
        elif method == 'eth_chainId':
            self.send_json({'id': rid, 'result': '0x3c', 'error': None})  # ETC chain ID = 61
        elif method == 'net_version':
            self.send_json({'id': rid, 'result': '61', 'error': None})
        else:
            self.send_json({'id': rid, 'result': None,
                            'error': {'code': -32601, 'message': f'Method not found: {method}'}})


# ──────────────────────────────────────────────────────────────────────────────
# Equihash  —  Zcash JSON-RPC  (port 8232)
# Uses getblocktemplate (Zcash variant) / submitblock
# ──────────────────────────────────────────────────────────────────────────────

class EquihashState:
    def __init__(self):
        self.height    = 2200000
        self.prevhash  = 'c' * 64
        self.bits      = '1e000fff'
        self.lock      = threading.Lock()
        self.submitted = []

    def get_block_template(self):
        with self.lock:
            target = bits_to_target(self.bits)
            # Zcash coinbase has no witness, uses Sapling/Orchard outputs
            coinbase_tx = make_coinbase_tx(self.height)
            coinbase_txid = sha256d(coinbase_tx)[::-1].hex()
            sapling_root = hashlib.sha256(f'sapling_{self.height}'.encode()).hexdigest()
            return {
                'version':               4,
                'previousblockhash':     self.prevhash,
                'blockcommitmentshash':  sapling_root,
                'lightclientroothash':   sapling_root,
                'finalsaplingroothash':  sapling_root,
                'authdataroot':          '0' * 64,
                'transactions':          [],
                'coinbasetxn': {
                    'data': coinbase_tx.hex(),
                    'txid': coinbase_txid,
                    'depends': [], 'fee': 0, 'sigops': 1,
                },
                'coinbasevalue':  312500000,
                'target':         target,
                'mintime':        int(time.time()) - 600,
                'mutable':        ['time', 'transactions', 'prevblock', 'coinbase/append'],
                'noncerange':     '00000000ffffffff',
                'curtime':        int(time.time()),
                'bits':           self.bits,
                'height':         self.height,
            }

    def submit(self, blob: str):
        with self.lock:
            self.submitted.append({'blob': blob, 'height': self.height})
            self.height += 1
            print(f"  [EQUIHSH] Block accepted! New height: {self.height}")
            return None

_equihash_state = EquihashState()

class EquihashHandler(BaseMockHandler):
    ALGO = 'equihash'

    def do_POST(self):
        req = self.read_body()
        method = req.get('method', '')
        rid    = req.get('id', 0)
        params = req.get('params', [])

        if method == 'getblocktemplate':
            self.send_json({'id': rid, 'result': _equihash_state.get_block_template(), 'error': None})
        elif method == 'submitblock':
            blob = params[0] if params else ''
            self.send_json({'id': rid, 'result': _equihash_state.submit(blob), 'error': None})
        elif method == 'getblockchaininfo':
            self.send_json({'id': rid, 'result': {
                'chain': 'main', 'blocks': _equihash_state.height,
            }, 'error': None})
        else:
            self.send_json({'id': rid, 'result': None,
                            'error': {'code': -32601, 'message': f'Method not found: {method}'}})


# ──────────────────────────────────────────────────────────────────────────────
# X11  —  Dash Core JSON-RPC  (port 9998)
# Same wire format as Bitcoin Core
# ──────────────────────────────────────────────────────────────────────────────

class X11State:
    def __init__(self):
        self.height    = 2000000
        self.prevhash  = 'd' * 64
        self.bits      = '1a0fffff'
        self.lock      = threading.Lock()
        self.submitted = []

    def get_block_template(self):
        with self.lock:
            coinbase_tx = make_coinbase_tx(self.height)
            coinbase_txid = sha256d(coinbase_tx)[::-1].hex()
            target = bits_to_target(self.bits)
            return {
                'version':           0x20000000,
                'previousblockhash': self.prevhash,
                'transactions':      [],
                'coinbasetxn': {
                    'data': coinbase_tx.hex(),
                    'txid': coinbase_txid,
                    'hash': coinbase_txid,
                    'depends': [], 'fee': 0, 'sigops': 1, 'weight': 500,
                },
                'coinbasevalue':     156250000,  # 1.5625 DASH
                'target':            target,
                'mintime':           int(time.time()) - 600,
                'mutable':           ['time', 'transactions', 'prevblock', 'coinbase/append'],
                'noncerange':        '00000000ffffffff',
                'curtime':           int(time.time()),
                'bits':              self.bits,
                'height':            self.height,
                'masternode_payments': True,
                'superblocks_started': True,
            }

    def submit(self, blob: str):
        with self.lock:
            self.submitted.append({'blob': blob, 'height': self.height})
            self.height += 1
            print(f"  [X11    ] Block accepted! New height: {self.height}")
            return None

_x11_state = X11State()

class X11Handler(BaseMockHandler):
    ALGO = 'x11'

    def do_POST(self):
        req = self.read_body()
        method = req.get('method', '')
        rid    = req.get('id', 0)
        params = req.get('params', [])

        if method == 'getblocktemplate':
            self.send_json({'id': rid, 'result': _x11_state.get_block_template(), 'error': None})
        elif method == 'submitblock':
            blob = params[0] if params else ''
            self.send_json({'id': rid, 'result': _x11_state.submit(blob), 'error': None})
        elif method in ('getmininginfo', 'getblockchaininfo'):
            self.send_json({'id': rid, 'result': {'blocks': _x11_state.height, 'chain': 'main'}, 'error': None})
        else:
            self.send_json({'id': rid, 'result': None,
                            'error': {'code': -32601, 'message': f'Method not found: {method}'}})


# ──────────────────────────────────────────────────────────────────────────────
# kHeavyHash  —  Kaspa REST API  (port 16110)
# GET  /info/getBlockTemplate?payAddress=...  -> JSON block template
# POST /blocks                                -> submit block
# GET  /info/blockdag                         -> chain info
# ──────────────────────────────────────────────────────────────────────────────

class KaspaState:
    def __init__(self):
        self.daa_score  = 85000000
        self.blue_score = 85000000
        self.lock       = threading.Lock()
        self.submitted  = []
        self.prev_hash  = 'e' * 64

    def get_block_template(self, pay_address: str):
        with self.lock:
            ts = int(time.time() * 1000)  # Kaspa uses millisecond timestamps
            header = {
                'version':              1,
                'parentsByLevel':       [[{'parentHash': self.prev_hash}]],
                'hashMerkleRoot':       hashlib.sha256(f'merkle_{self.daa_score}'.encode()).hexdigest(),
                'acceptedIdMerkleRoot': '0' * 64,
                'utxoCommitment':       '0' * 64,
                'timestamp':            str(ts),
                'bits':                 486539008,   # 0x1d0fffff — low difficulty
                'nonce':                '0',
                'daaScore':             str(self.daa_score),
                'blueWork':             '0' * 14,
                'blueScore':            str(self.blue_score),
                'pruningPoint':         '0' * 64,
            }
            return {
                'block': {
                    'header':       header,
                    'transactions': [{
                        'inputs':  [],
                        'outputs': [{
                            'amount':          '500000000000',
                            'scriptPublicKey': {'scriptPublicKey': '20' + pay_address[:40]},
                        }],
                        'lockTime': 0,
                        'subnetworkId': '0100000000000000000000000000000000000000',
                        'payload':  pay_address.encode('utf-8').hex()[:128],
                    }],
                },
                'isSynced': True,
            }

    def submit(self, block: dict):
        with self.lock:
            self.submitted.append({'block': block, 'daa': self.daa_score})
            header = block.get('header', {})
            self.prev_hash = hashlib.sha256(
                json.dumps(header, sort_keys=True).encode()).hexdigest()
            self.daa_score  += 1
            self.blue_score += 1
            print(f"  [KASPA  ] Block accepted! New DAA score: {self.daa_score}")
            return {}

_kaspa_state = KaspaState()

class KaspaHandler(BaseMockHandler):
    ALGO = 'kaspa'

    def do_GET(self):
        parsed = urlparse(self.path)
        qs     = parse_qs(parsed.query)

        if parsed.path in ('/info/getBlockTemplate', '/api/getBlockTemplate',
                           '/api/v1/getBlockTemplate'):
            pay_address = qs.get('payAddress', ['kaspa:qtest'])[0]
            self.send_json(_kaspa_state.get_block_template(pay_address))

        elif parsed.path in ('/info/blockdag', '/api/blockdag'):
            with _kaspa_state.lock:
                self.send_json({
                    'networkName':    'kaspa-mainnet',
                    'blockCount':     str(_kaspa_state.daa_score),
                    'headerCount':    str(_kaspa_state.daa_score),
                    'difficulty':     0.001,
                    'pastMedianTime': str(int(time.time() * 1000)),
                    'virtualDaaScore': str(_kaspa_state.daa_score),
                })

        elif parsed.path == '/info/peerAddresses':
            self.send_json({'peerAddresses': []})

        else:
            self.send_json({'error': f'Unknown GET path: {parsed.path}'}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        body   = self.read_body()

        if parsed.path in ('/blocks', '/api/blocks', '/api/v1/blocks'):
            block = body.get('block', body)
            self.send_json(_kaspa_state.submit(block))

        else:
            self.send_json({'error': f'Unknown POST path: {parsed.path}'}, 404)


# ──────────────────────────────────────────────────────────────────────────────
# Server launcher
# ──────────────────────────────────────────────────────────────────────────────

DAEMONS = {
    'sha256d':  (SHA256dHandler,  8332,  'Bitcoin/SHA256d   (BTC, BCH, BSV)'),
    'scrypt':   (ScryptHandler,   9332,  'Litecoin/Scrypt   (LTC, DOGE)'),
    'ethash':   (EthashHandler,   8545,  'ETC/Ethash        (ETC, OCTA, ETHO, DC)'),
    'equihash': (EquihashHandler, 8232,  'Zcash/Equihash    (ZEC, ZEN, KMD)'),
    'x11':      (X11Handler,      9998,  'Dash/X11          (DASH, POLIS)'),
    'kaspa':    (KaspaHandler,    16110, 'Kaspa/kHeavyHash  (KAS, PYI, KLS, SPR)'),
}

def start_daemon(name: str, handler_cls, port: int, label: str) -> threading.Thread:
    def run():
        server = http.server.HTTPServer(('0.0.0.0', port), handler_cls)
        print(f"  ✓  {label:45s}  port {port}", flush=True)
        server.serve_forever()

    t = threading.Thread(target=run, name=f'mock-{name}', daemon=True)
    t.start()
    return t


def main():
    parser = argparse.ArgumentParser(description='WATTx AuxPoW mock daemon suite')
    parser.add_argument('--algo', choices=list(DAEMONS.keys()),
                        help='Start only this algorithm daemon (default: all)')
    args = parser.parse_args()

    targets = {args.algo: DAEMONS[args.algo]} if args.algo else DAEMONS

    print()
    print('=' * 60)
    print('  WATTx AuxPoW Mock Daemon Suite')
    print('=' * 60)
    print()
    print('  Starting mock daemons:')
    threads = []
    for name, (handler_cls, port, label) in targets.items():
        threads.append(start_daemon(name, handler_cls, port, label))

    time.sleep(0.3)
    print()
    print('  All daemons running.  Ctrl-C to stop.')
    print('=' * 60)
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n  Shutting down.')


if __name__ == '__main__':
    main()
