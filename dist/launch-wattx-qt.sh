#!/bin/bash
# Launch script for WATTx Qt Wallet
# This script bypasses potential Qt theme issues

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QT_QPA_PLATFORMTHEME="" "$DIR/wattx-qt" "$@"
