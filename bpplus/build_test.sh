#!/bin/bash
# Reproducible build + test of the isolated libwattx_bpplus port (Monero
# Bulletproofs+ over ed25519). NOT linked into wattxd. Run from this directory.
set -e
cd "$(dirname "$0")"
O=/tmp/bpplus_obj; mkdir -p $O
CINC="-I. -Icrypto"
CXXINC="-I. -Icrypto -Iringct"

echo "[*] compiling C leaf crypto..."
gcc -O2 $CINC -c crypto/crypto-ops.c      -o $O/crypto-ops.o
gcc -O2 $CINC -c crypto/crypto-ops-data.c -o $O/crypto-ops-data.o
gcc -O2 $CINC -c crypto/keccak.c          -o $O/keccak.o
gcc -O2 $CINC -c ringct/rctCryptoOps.c    -o $O/rctCryptoOps.o
gcc -O2 $CINC -c common/aligned.c         -o $O/aligned.o

echo "[*] compiling C++ ringct + BP+..."
g++ -std=c++17 -O2 $CXXINC -c ringct/rctTypes.cpp        -o $O/rctTypes.o
g++ -std=c++17 -O2 $CXXINC -c ringct/rctOps.cpp          -o $O/rctOps.o
g++ -std=c++17 -O2 $CXXINC -c ringct/multiexp.cc         -o $O/multiexp.o
g++ -std=c++17 -O2 $CXXINC -c ringct/bulletproofs_plus.cc -o $O/bulletproofs_plus.o
g++ -std=c++17 -O2 $CXXINC -c bpplus_support.cpp         -o $O/support.o

echo "[*] archiving static lib libwattx_bpplus.a..."
ar rcs $O/libwattx_bpplus.a \
  $O/crypto-ops.o $O/crypto-ops-data.o $O/keccak.o $O/rctCryptoOps.o $O/aligned.o \
  $O/rctTypes.o $O/rctOps.o $O/multiexp.o $O/bulletproofs_plus.o $O/support.o

echo "[*] building + running the prove/verify test..."
g++ -std=c++17 -O2 $CXXINC -c test/bpplus_test.cpp -o $O/test.o
g++ $O/test.o $O/libwattx_bpplus.a -o $O/bpplus_test
$O/bpplus_test
