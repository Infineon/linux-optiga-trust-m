#!/bin/sh

FILE="0001-trust_m_lib.patch"

sudo apt update 
sudo apt -y install git gcc libssl-dev

echo "-----> Apply patch"
cd trustm_lib
git reset --hard
cd ..
git apply $FILE

set -e
echo "-----> Build Trust M Linux Tools and provider"
sudo make uninstall
make clean
make -j5
sudo make install

echo "-----> Build Protected Update Set tool"
cd ex_protected_update_data_set/Linux/
make clean
make -j5 
sudo make install 
