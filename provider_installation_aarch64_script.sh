#!/bin/sh

FILE="0001-trust_m_lib.patch"

sudo apt update 
#~ sudo apt -y install git gcc 

echo "-----> Apply patch"
git apply $FILE

set -e
echo "-----> Build Trust M Linux Tools for aarch64"

sudo make uninstall AARCH64=YES
make clean AARCH64=YES
make -j5 AARCH64=YES
sudo make install AARCH64=YES





