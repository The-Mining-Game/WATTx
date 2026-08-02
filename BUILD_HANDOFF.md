# WATTx wallet build — handoff

Everything below is already committed on branch `feat/multi-algo-auxpow-merged-mining`
in `~/Documents/WATTx/WATTx-0.1.7-dev`. Nothing needs to be re-edited; this
explains what changed and how to build and ship it.

HEAD when written: `f5e14da7`

## What changed

### Consensus (all activate at height 2000 on mainnet; live and verified)

| Commit | Fix |
|---|---|
| `3892d980` | PoW difficulty could never retarget — `fPowNoRetargeting` (a regtest flag) was true on mainnet, so `CalculateNextWorkRequired` returned the previous block's nBits forever. Gated behind new `nPowRetargetHeight` so blocks mined under the old rule stay valid. |
| `2bd54be5` | Per-algorithm difficulty was dead code (`GetNextWorkRequiredForAlgorithm` had no callers) — all 7 merged-mining algorithms shared one difficulty. Now routed per algorithm. Also moved `nX25XActivationHeight` and `nPoSDifficultyFixHeight` from 210000 to 2000. |
| `6faa8c12` | Templates are built per algorithm (`pow_algo` in `BlockCreateOptions`) so nBits matches the algorithm stamped in the block version. Without this every merged block fails `bad-diffbits` at the activation height and the chain stalls. |
| `4adf3023` | Coinbase maturity 1 → 100, matching `nMaxReorgDepth`. |

Verified on the live chain: block 1999 `bits=1f00ffff` (frozen) → block 2000
`bits=1e744164` (retargeted), zero rejections, blocks carry `version=20010300`
(the `03` is RandomX).

### Graphics (this is the part the other session did not have)

| File | Now contains |
|---|---|
| `src/qt/res/icons/bitcoin.png` (1024²) | WATTx logo — yellow gradient, blue shadow, lightning bolt. App + tray icon. |
| `src/qt/res/icons/logo.png` (250²) | Same logo, splash size. |
| `src/qt/res/styles/theme{1,2,3}/app-icons/splash_bg.png` | Binary-code WATTx logo on navy (`wattx_logo_binary.png`). |
| `src/qt/res/styles/theme{1,2,3}/app-icons/bg.png` | Yellow diagonal WTX pattern (replaces Qtum chain artwork). |
| `src/qt/splashscreen.cpp` | Draws the logo with `QIcon(...)` instead of `PlatformStyle::SingleColorIcon(...)`. |

Sources: `~/Documents/WATTx/wattx-qt-graphics/wattx_logo.png` and
`wattx_logo_binary.png`. Originals preserved as `*.qtum.bak` and
`*.preWattxLogo.bak` — do not delete them.

**The `SingleColorIcon` change matters:** that call flattens any icon to one
solid colour. Leave it in and the new logo renders as a plain white silhouette
with the gradient and bolt gone — the artwork looks broken but the artwork is
fine.

Graphics live in the Qt resource bundle, so **any graphics change needs a
rebuild of `wattx-qt`** to appear. Copying PNGs next to the binary does nothing.

### Other fixes in this branch

- `19b5796a` — headers messages carried an AuxPoW payload no receiver parsed, so
  fresh nodes could never sync from genesis.
- `dbda47f1` — three XMRig protocol bugs (missing `algo` field, byte-swapped
  share target, object-form submits rejected) that made the randomx pool
  unmineable by stock miners.
- `4e87aa7f`, `50806c28` — Android (arm64) cross-build support in `depends`.

## Build

```bash
cd ~/Documents/WATTx/WATTx-0.1.7-dev

# Linux (native)
cmake --build build -j6 --target wattxd wattx-qt wattx-cli wattx-tx wattx-util wattx-wallet

# Windows (mingw cross; depends already built in depends/x86_64-w64-mingw32)
cmake --build build-win -j5
```

Do not reconfigure cmake unless something forces it — `build-win` already has
`BUILD_GUI=ON`, the right `CARGO_EXECUTABLE` and the depends toolchain file.
A fresh configure is where the four known Windows gotchas bite (see
`contrib/package_releases.sh` history).

## Package and publish

```bash
cd ~/Documents/WATTx/WATTx-0.1.7-dev
bash contrib/package_releases.sh      # -> wattx-0.1.7.2-linux64.tar.gz, -win64.zip

gh release upload v0.1.7.2 \
  wattx-0.1.7.2-linux64.tar.gz wattx-0.1.7.2-win64.zip \
  --clobber --repo WATTxChain/WATTx
gh release upload v0.1.7.2 \
  wattx-0.1.7.2-linux64.tar.gz wattx-0.1.7.2-win64.zip \
  --clobber --repo nucash-mining/WATTxchain
```

`package_releases.sh` runs patchelf (`$ORIGIN` rpath) so the Linux binaries
double-click without `LD_LIBRARY_PATH`, and strips the Windows exes.

**Release note to include:** every node must upgrade — nodes on older builds
reject blocks from height 2000 onward.

## Deploying to the running node (legion, 10.42.0.86)

```bash
scp build/bin/wattxd nuts@10.42.0.86:/tmp/wattxd.new
ssh nuts@10.42.0.86 '
  mv /tmp/wattxd.new ~/wattx-stack/bin-mainnet/wattxd
  chmod +x ~/wattx-stack/bin-mainnet/wattxd
  docker restart wattxd-mainnet'
```

Then **restart the stratum and miner** — a daemon restart always drops the
stratum config, and without this the chain simply stops advancing:

```bash
ssh nuts@10.42.0.86 'docker exec -i wattxd-mainnet bash -c \
  "curl -s --user wattxrpc:8a51ce1e12f2b7c33d1de29d1c34f7a2 \
   -H \"content-type:application/json\" http://127.0.0.1:3889/ --data @-"' \
  < start_stratum_legion.json
ssh nuts@10.42.0.86 'docker restart wattx-miner'
```

Block production pauses 2–4 minutes after a stratum restart while the job cycle
and RandomX dataset re-initialise. That is normal, not a broken submit path.

## Local wallet

```bash
pkill -x wattx-qt
cp build/bin/wattx-qt ~/wattx-0.1.7.2/wattx-qt
~/.local/bin/patchelf --set-rpath '$ORIGIN' ~/wattx-0.1.7.2/wattx-qt
cd ~/wattx-0.1.7.2 && DISPLAY=:0.0 setsid nohup ./wattx-qt \
  -datadir=$HOME/.wattx-qt-0172 -listen=0 > ~/.wattx-qt-0172/qt.out 2>&1 &
```

## Still open

- **Supply cap mismatch.** Emission totals ~10.43M WTX (5 WTX/block, halving
  every 1,051,200 blocks, forced to zero after 7 halvings in
  `GetBlockSubsidy`), but the wallet's Explorer tab advertises 21,000,000 WTX.
  Either correct the display or change emission — the latter is a consensus
  change and gets more expensive every block.
- Android core port: depends builds for arm64, core configures and compiles
  ~13%, blocked on NDK 25's libc++ lacking C++20 concepts (NDK r27 is installed
  at `~/Android/Sdk/ndk/27.*`) and a missing libsodium recipe for that host.
