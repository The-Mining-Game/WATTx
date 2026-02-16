#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="$DIR:$LD_LIBRARY_PATH"
QT_QPA_PLATFORMTHEME="" "$DIR/wattx-qt" "$@"
