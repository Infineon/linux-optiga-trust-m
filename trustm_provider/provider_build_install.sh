#!/bin/sh

set -e

FILE="../0001-trust_m_lib.patch"

git apply $FILE

echo "-----> Build Trust M provider"

set -x

sudo make uninstall
make clean
make -j5
sudo make install
