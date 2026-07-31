#!/bin/bash
# Package WATTx 0.1.7.2 release archives from the current build trees.
#   linux: build/bin      -> release-linux64/ -> wattx-0.1.7.2-linux64.tar.gz
#   win:   build-win/bin  -> release-win64/   -> wattx-0.1.7.2-win64.zip
# Run from the repo root after both builds succeed.
set -e
cd "$(dirname "$0")/.."
VER=0.1.7.2
PE=$(ls "$HOME/.local/bin/patchelf" 2>/dev/null || command -v patchelf)

echo "== linux =="
for b in wattx-qt wattxd wattx-cli wattx-tx wattx-util wattx-wallet; do
  cp "build/bin/$b" "release-linux64/$b"
  "$PE" --set-rpath '$ORIGIN' "release-linux64/$b"
done
cp build/bin/librandomx.so release-linux64/ 2>/dev/null || true
rm -f "release-linux64/wattx-"*.tar.gz
tar -C release-linux64 -czf "wattx-$VER-linux64.tar.gz" \
  wattx-qt wattxd wattx-cli wattx-tx wattx-util wattx-wallet \
  librandomx.so wattx-icon.png install-desktop.sh wattx.conf.example README.txt
echo "  -> wattx-$VER-linux64.tar.gz ($(du -h wattx-$VER-linux64.tar.gz | cut -f1))"

echo "== windows =="
for b in wattx-qt wattxd wattx-cli wattx-tx wattx-util wattx-wallet; do
  cp "build-win/bin/$b.exe" "release-win64/$b.exe"
  x86_64-w64-mingw32-strip "release-win64/$b.exe"
done
# runtime DLLs: keep the ones already curated in release-win64 (libgcc/libstdc++/
# libwinpthread/librandomx). Refresh librandomx.dll if the build produced one.
find build-win -name 'librandomx.dll' -exec cp {} release-win64/ \; 2>/dev/null || true
# Qt platform plugin required for double-click launch
if [ -d depends/x86_64-w64-mingw32/plugins/platforms ]; then
  mkdir -p release-win64/platforms
  cp depends/x86_64-w64-mingw32/plugins/platforms/qwindows*.dll release-win64/platforms/ 2>/dev/null || true
fi
rm -f "release-win64/wattx-"*.zip
(cd release-win64 && zip -qr "../wattx-$VER-win64.zip" \
  wattx-qt.exe wattxd.exe wattx-cli.exe wattx-tx.exe wattx-util.exe wattx-wallet.exe \
  *.dll platforms wattx.conf.example README.txt launch-wattx-qt.bat launch-wattxd.bat)
echo "  -> wattx-$VER-win64.zip ($(du -h wattx-$VER-win64.zip | cut -f1))"
