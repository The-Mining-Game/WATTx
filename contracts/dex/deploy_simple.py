#!/usr/bin/env python3
"""Deploy SimpleDEX and TestToken contracts to testnet"""
import subprocess
import json
import sys
import os

os.chdir("/home/nuts/Documents/WATTx/contracts/dex")

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

def get_bytecode(sol_file, contract_name):
    """Compile and get bytecode"""
    result = subprocess.run(
        ["solc", "--evm-version", "istanbul", "--optimize", "--optimize-runs", "200", "--bin", sol_file],
        capture_output=True, text=True
    )
    lines = result.stdout.split('\n')
    for i, line in enumerate(lines):
        if contract_name in line and "Binary:" in lines[i+1] if i+1 < len(lines) else False:
            # Next non-empty line is bytecode
            for j in range(i+2, len(lines)):
                if lines[j].strip() and lines[j].strip().startswith('60'):
                    return lines[j].strip()
    return None

def encode_address(addr):
    """Pad address to 32 bytes"""
    if addr.startswith('0x'):
        addr = addr[2:]
    return addr.zfill(64)

# Compile and deploy TokenA
print("Compiling TestToken...")
token_bytecode = get_bytecode("TestToken.sol", "TestToken")
if not token_bytecode:
    print("Failed to compile TestToken")
    sys.exit(1)
print(f"Token bytecode length: {len(token_bytecode)}")

# Encode constructor args for TokenA: "TokenA", "TKNA", 1000000
# ABI: offset(name), offset(symbol), amount, name_len, name_data, symbol_len, symbol_data
def encode_string(s):
    length = hex(len(s))[2:].zfill(64)
    data = s.encode().hex().ljust(64, '0')
    return length + data

# Constructor(string name, string symbol, uint256 initialSupply)
# Layout: offset_name(0x60), offset_symbol(0xa0), initialSupply, name_len, name_pad, symbol_len, symbol_pad
token_a_args = (
    "0000000000000000000000000000000000000000000000000000000000000060"  # offset to name
    "00000000000000000000000000000000000000000000000000000000000000a0"  # offset to symbol
    "00000000000000000000000000000000000000000000000000000000000f4240"  # 1000000
    + encode_string("TokenA")
    + encode_string("TKNA")
)

print("\nDeploying TokenA...")
result = run_cli(["createcontract", token_bytecode + token_a_args, "3000000"])
if result:
    data = json.loads(result)
    token_a_addr = data['address']
    print(f"TokenA deployed at: {token_a_addr}")
    with open("deployed_tokenA.txt", "w") as f:
        f.write(token_a_addr)
else:
    print("Failed to deploy TokenA")
    sys.exit(1)

# Deploy TokenB
token_b_args = (
    "0000000000000000000000000000000000000000000000000000000000000060"
    "00000000000000000000000000000000000000000000000000000000000000a0"
    "00000000000000000000000000000000000000000000000000000000001e8480"  # 2000000
    + encode_string("TokenB")
    + encode_string("TKNB")
)

print("\nDeploying TokenB...")
result = run_cli(["createcontract", token_bytecode + token_b_args, "3000000"])
if result:
    data = json.loads(result)
    token_b_addr = data['address']
    print(f"TokenB deployed at: {token_b_addr}")
    with open("deployed_tokenB.txt", "w") as f:
        f.write(token_b_addr)
else:
    print("Failed to deploy TokenB")
    sys.exit(1)

# Mine to confirm tokens
print("\nMining blocks to confirm tokens...")
addr = run_cli(["getnewaddress"])
run_cli(["generatetoaddress", "3", addr])

# Get SimpleDEX bytecode
print("\nCompiling SimpleDEX...")
dex_bytecode = get_bytecode("SimpleDEX.sol", "SimpleDEX")
if not dex_bytecode:
    print("Failed to compile SimpleDEX")
    sys.exit(1)
print(f"DEX bytecode length: {len(dex_bytecode)}")

# Constructor args: token0, token1
dex_args = encode_address(token_a_addr) + encode_address(token_b_addr)

print(f"\nDeploying SimpleDEX with tokens: {token_a_addr}, {token_b_addr}...")
result = run_cli(["createcontract", dex_bytecode + dex_args, "3000000"])
if result:
    data = json.loads(result)
    dex_addr = data['address']
    print(f"SimpleDEX deployed at: {dex_addr}")
    with open("deployed_swap.txt", "w") as f:
        f.write(dex_addr)
else:
    print("Failed to deploy SimpleDEX")
    sys.exit(1)

# Mine to confirm
print("\nMining blocks to confirm DEX...")
run_cli(["generatetoaddress", "3", addr])

# Verify deployments
print("\n=== Verifying Deployments ===")
for name, addr_file in [("TokenA", "deployed_tokenA.txt"), ("TokenB", "deployed_tokenB.txt"), ("SimpleDEX", "deployed_swap.txt")]:
    with open(addr_file) as f:
        addr = f.read().strip()
    result = run_cli(["getaccountinfo", addr])
    if result:
        info = json.loads(result)
        print(f"{name} ({addr}): code_size={len(info.get('code', ''))//2} bytes")
    else:
        print(f"{name} ({addr}): FAILED TO VERIFY")

print("\n=== Deployment Complete ===")
print(f"TokenA: {token_a_addr}")
print(f"TokenB: {token_b_addr}")
print(f"SimpleDEX: {dex_addr}")
