#!/bin/sh

FILE="0001-trust_m_lib.patch"

sudo apt update 
sudo apt -y install git gcc libssl-dev

echo "-----> Apply patch"
git apply $FILE

echo "-----> Build Trust M provider"

set -e

sudo make uninstall
make clean
make -j5
sudo make install
