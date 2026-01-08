#!/usr/bin/env python3
"""Deploy SimpleToken and SimpleDEX contracts to testnet"""
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

def compile_contract(sol_file):
    """Compile and get bytecode"""
    result = subprocess.run(
        ["solc", "--evm-version", "istanbul", "--optimize", "--optimize-runs", "200",
         "--metadata-hash", "none", "--bin", sol_file],
        capture_output=True, text=True
    )
    lines = result.stdout.split('\n')
    for line in lines:
        if line.strip().startswith('6080604052'):
            return line.strip()
    return None

def wait_for_confirmation(txid):
    """Wait for transaction confirmation"""
    import time
    for _ in range(10):
        result = run_cli(["gettransactionreceipt", txid])
        if result:
            receipt = json.loads(result)
            if receipt and len(receipt) > 0:
                r = receipt[0]
                if r.get("excepted") == "None":
                    return r.get("contractAddress")
                else:
                    print(f"Contract failed: {r.get('excepted')}")
                    return None
        time.sleep(1)
    return None

# Deploy simple test first
print("Deploying SimpleTest to verify EVM works...")
test_bc = compile_contract("SimpleTest.sol")
result = run_cli(["createcontract", test_bc, "500000"])
if result:
    data = json.loads(result)
    print(f"SimpleTest TX: {data['txid']}")
    print(f"Expected addr: {data['address']}")

    # Mine and wait
    addr = run_cli(["getnewaddress"])
    run_cli(["generatetoaddress", "1", addr])

    contract_addr = wait_for_confirmation(data['txid'])
    if contract_addr:
        print(f"SimpleTest confirmed at: {contract_addr}")
        # Verify it works
        result = run_cli(["getaccountinfo", contract_addr])
        if result:
            info = json.loads(result)
            print(f"Code size: {len(info.get('code', ''))//2} bytes")
    else:
        print("SimpleTest failed!")
        sys.exit(1)

# Now deploy SimpleToken with constructor args
print("\nCompiling SimpleToken...")
token_bc = compile_contract("SimpleToken.sol")
if not token_bc:
    print("Failed to compile SimpleToken")
    sys.exit(1)
print(f"Token bytecode length: {len(token_bc)}")

# Constructor(string name, string symbol, uint256 supply)
# ABI encode the args
def encode_string(s):
    """Encode string for ABI - length + padded data"""
    length = len(s)
    length_hex = hex(length)[2:].zfill(64)
    data_hex = s.encode().hex()
    # Pad to 32-byte boundary
    padded_len = ((len(data_hex) + 63) // 64) * 64
    data_padded = data_hex.ljust(padded_len, '0')
    return length_hex + data_padded

# For constructor(string,string,uint256):
# Layout: offset(name)=0x60, offset(symbol)=0xa0, supply, then name data, then symbol data
name_data = encode_string("TokenA")
symbol_data = encode_string("TKNA")
supply = "00000000000000000000000000000000000000000000000000000000000f4240"  # 1000000

# Calculate offsets (in bytes from start of params):
# Param 1 (name offset): points to dynamic data start = 0x60 (96 bytes = 3 * 32)
# Param 2 (symbol offset): points after name data = 0x60 + len(name_data)/2
name_data_bytes = len(name_data) // 2
symbol_offset = 0x60 + name_data_bytes
symbol_offset_hex = hex(symbol_offset)[2:].zfill(64)

args = (
    "0000000000000000000000000000000000000000000000000000000000000060"  # offset to name
    + symbol_offset_hex  # offset to symbol
    + supply  # supply value
    + name_data  # name (length + padded string)
    + symbol_data  # symbol (length + padded string)
)

print(f"\nDeploying TokenA...")
full_bytecode = token_bc + args
print(f"Full bytecode length: {len(full_bytecode)}")

result = run_cli(["createcontract", full_bytecode, "5000000"])
if result:
    data = json.loads(result)
    print(f"TokenA TX: {data['txid']}")

    addr = run_cli(["getnewaddress"])
    run_cli(["generatetoaddress", "1", addr])

    token_a_addr = wait_for_confirmation(data['txid'])
    if token_a_addr:
        print(f"TokenA confirmed at: {token_a_addr}")
        with open("deployed_tokenA.txt", "w") as f:
            f.write(token_a_addr)
    else:
        print("TokenA deployment failed!")
        sys.exit(1)
else:
    print("Failed to submit TokenA")
    sys.exit(1)

# Deploy TokenB
print(f"\nDeploying TokenB...")
name_data_b = encode_string("TokenB")
symbol_data_b = encode_string("TKNB")
supply_b = "00000000000000000000000000000000000000000000000000000000001e8480"  # 2000000

name_data_b_bytes = len(name_data_b) // 2
symbol_offset_b = 0x60 + name_data_b_bytes
symbol_offset_b_hex = hex(symbol_offset_b)[2:].zfill(64)

args_b = (
    "0000000000000000000000000000000000000000000000000000000000000060"
    + symbol_offset_b_hex
    + supply_b
    + name_data_b
    + symbol_data_b
)

result = run_cli(["createcontract", token_bc + args_b, "5000000"])
if result:
    data = json.loads(result)
    print(f"TokenB TX: {data['txid']}")

    addr = run_cli(["getnewaddress"])
    run_cli(["generatetoaddress", "1", addr])

    token_b_addr = wait_for_confirmation(data['txid'])
    if token_b_addr:
        print(f"TokenB confirmed at: {token_b_addr}")
        with open("deployed_tokenB.txt", "w") as f:
            f.write(token_b_addr)
    else:
        print("TokenB deployment failed!")
        sys.exit(1)
else:
    print("Failed to submit TokenB")
    sys.exit(1)

# Deploy SimpleDEX
print("\nCompiling SimpleDEX...")
dex_bc = compile_contract("SimpleDEX.sol")
if not dex_bc:
    print("Failed to compile SimpleDEX")
    sys.exit(1)
print(f"DEX bytecode length: {len(dex_bc)}")

# Constructor(address token0, address token1)
dex_args = token_a_addr.zfill(64) + token_b_addr.zfill(64)

print(f"\nDeploying SimpleDEX with tokens...")
result = run_cli(["createcontract", dex_bc + dex_args, "5000000"])
if result:
    data = json.loads(result)
    print(f"DEX TX: {data['txid']}")

    addr = run_cli(["getnewaddress"])
    run_cli(["generatetoaddress", "1", addr])

    dex_addr = wait_for_confirmation(data['txid'])
    if dex_addr:
        print(f"SimpleDEX confirmed at: {dex_addr}")
        with open("deployed_swap.txt", "w") as f:
            f.write(dex_addr)
    else:
        print("SimpleDEX deployment failed!")
        sys.exit(1)
else:
    print("Failed to submit SimpleDEX")
    sys.exit(1)

print("\n=== Deployment Complete ===")
print(f"TokenA: {token_a_addr}")
print(f"TokenB: {token_b_addr}")
print(f"SimpleDEX: {dex_addr}")
