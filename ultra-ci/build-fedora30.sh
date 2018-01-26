#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(nproc)
export CROSS="ccache powerpc64-linux-gnu-"

make -j"${MAKE_J}" all
make -j"${MAKE_J}" check

make clean
rm -rf builddir
mkdir builddir
make SRC="$(pwd)" -f ../Makefile -C builddir -j"${MAKE_J}"
make clean