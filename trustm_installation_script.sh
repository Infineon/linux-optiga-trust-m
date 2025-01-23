#!/bin/sh


sudo apt update 
sudo apt -y install git gcc libssl-dev gpiod libgpiod-dev


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
