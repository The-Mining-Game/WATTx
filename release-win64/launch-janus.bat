@echo off
echo Starting WATTx Janus EVM Bridge...
echo Connect Rabby/MetaMask to: http://localhost:23889
echo Chain ID: 8890 (regtest) / 8889 (testnet) / 2335 (mainnet)
"%~dp0janus.exe" --qtum-rpc "http://user:password@127.0.0.1:18890" --qtum-network auto --bind 0.0.0.0 --port 23889 --dev %*
