#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(nproc)

export CROSS="ccache powerpc64le-linux-gnu-"

make -j"${MAKE_J}" all
make -j"${MAKE_J}" check
## (andmike) Will try GCOV later
#SKIBOOT_GCOV=1 make -j${MAKE_J}
#SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC="$(pwd)" -f ../Makefile -C builddir -j"${MAKE_J}"
make clean

# Address errors in tss prior to enabling
echo "Disabled Building with clang..."
#make clean
#make -j${MAKE_J} CC=clang
#make -j${MAKE_J} CC=clang check
