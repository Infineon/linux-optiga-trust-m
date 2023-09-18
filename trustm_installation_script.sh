#!/bin/sh

FILE="0001-trust_m_lib.patch"
TRUSTM_LIB_PATH="${PWD}trustm_lib/"
CURRENT_DIR="${PWD}"
PATCH="${PWD}/${FILE}"


sudo apt update 
sudo apt -y install awscli git gcc libssl-dev

echo $PATCH
echo $TRUSTM_LIB_PATH

echo "-----> Apply patch"
git apply $FILE
set -e
echo "-----> Build Trust M Linux Tools"
make clean
sudo make uninstall 
make -j5 
sudo make install 
echo "-----> Build Protected Update Set tool"
cd ex_protected_update_data_set/Linux/
make clean
make -j5 
sudo make install 
 
#~cd $CURRENT_DIR
echo "-----> Installation completed. Back to ${PWD}"



