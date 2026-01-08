#!/usr/bin/env python3
"""Deploy WATTxSwap and TestToken contracts to testnet"""
import subprocess
import json
import sys

CLI = "/home/nuts/Documents/WATTx/build/bin/wattx-cli"
DATADIR = "/home/nuts/.wattx_testnet"
RPC_USER = "wattx"
RPC_PASS = "wattxtest123"

def run_cli(cmd):
    """Run wattx-cli command and return result"""
    full_cmd = [CLI, f"-datadir={DATADIR}", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}"] + cmd
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return None
    return result.stdout.strip()

# Read bytecode files
with open("/home/nuts/Documents/WATTx/contracts/dex/swap_bytecode.hex", "r") as f:
    swap_bytecode = f.read().strip()

# Deploy WATTxSwap
print("Deploying WATTxSwap...")
result = run_cli(["createcontract", swap_bytecode, "6000000"])
if result:
    data = json.loads(result)
    print(f"WATTxSwap deployed!")
    print(f"  TXID: {data['txid']}")
    print(f"  Address: {data['address']}")
    with open("/home/nuts/Documents/WATTx/contracts/dex/deployed_swap.txt", "w") as f:
        f.write(data['address'])
else:
    print("Failed to deploy WATTxSwap")
    sys.exit(1)

# Read token bytecode
with open("/home/nuts/Documents/WATTx/contracts/dex/token_bytecode.hex", "r") as f:
    token_bytecode = f.read().strip()

# Encode constructor args for TokenA: "TokenA", "TKNA", 1000000
# ABI encoding: offset(0x60), offset(0xa0), amount, name_length, name, symbol_length, symbol
def encode_string(s):
    """Encode string for ABI"""
    encoded = s.encode().hex()
    length = hex(len(s))[2:].zfill(64)
    # Pad to 32 bytes
    padded = encoded.ljust(64, '0')
    return length + padded

# Simple ABI encoding for constructor(string, string, uint256)
# offset for name, offset for symbol, amount
amount_a = hex(1000000)[2:].zfill(64)
name_a_data = encode_string("TokenA")
symbol_a_data = encode_string("TKNA")

# Construct ABI: offset to name (0x60), offset to symbol (0xa0), amount
token_a_args = "0000000000000000000000000000000000000000000000000000000000000060"  # offset to name (96)
token_a_args += "00000000000000000000000000000000000000000000000000000000000000a0"  # offset to symbol (160)
token_a_args += amount_a  # initial supply
token_a_args += name_a_data  # name data
token_a_args += symbol_a_data  # symbol data

print("\nDeploying TokenA...")
result = run_cli(["createcontract", token_bytecode + token_a_args, "3000000"])
if result:
    data = json.loads(result)
    print(f"TokenA deployed!")
    print(f"  TXID: {data['txid']}")
    print(f"  Address: {data['address']}")
    with open("/home/nuts/Documents/WATTx/contracts/dex/deployed_tokenA.txt", "w") as f:
        f.write(data['address'])
else:
    print("Failed to deploy TokenA")
    sys.exit(1)

# Deploy TokenB
amount_b = hex(2000000)[2:].zfill(64)
name_b_data = encode_string("TokenB")
symbol_b_data = encode_string("TKNB")

token_b_args = "0000000000000000000000000000000000000000000000000000000000000060"
token_b_args += "00000000000000000000000000000000000000000000000000000000000000a0"
token_b_args += amount_b
token_b_args += name_b_data
token_b_args += symbol_b_data

print("\nDeploying TokenB...")
result = run_cli(["createcontract", token_bytecode + token_b_args, "3000000"])
if result:
    data = json.loads(result)
    print(f"TokenB deployed!")
    print(f"  TXID: {data['txid']}")
    print(f"  Address: {data['address']}")
    with open("/home/nuts/Documents/WATTx/contracts/dex/deployed_tokenB.txt", "w") as f:
        f.write(data['address'])
else:
    print("Failed to deploy TokenB")
    sys.exit(1)

print("\nAll contracts deployed! Mining blocks to confirm...")
# Generate a block to confirm
result = run_cli(["getnewaddress"])
if result:
    result = run_cli(["generatetoaddress", "5", result])
    if result:
        print("Blocks mined successfully!")

print("\nDeployment complete!")
