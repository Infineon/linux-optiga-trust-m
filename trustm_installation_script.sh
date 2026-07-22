#!/bin/sh
sudo apt update
sudo apt -y install git gcc build-essential libssl-dev gpiod libgpiod-dev curl xxd cmake



set -e
echo "-----> Build Trust M Linux Tools and provider"
#Generate necessary file for mbedtls-4.x and tf-psa-1.x
(
    echo "-----> Generate mbedtls config files" 
    cd trustm_lib/external/mbedtls-4.x 
    python3 framework/scripts/make_generated_files.py
)
(
    echo "-----> Generate PSA config files"
    cd trustm_lib/external/mbedtls-4.x/tf-psa-crypto \ 
    python3 framework/scripts/make_generated_files.py
)

sudo make uninstall 
make clean 
make -j5 
sudo make install 
echo "-----> Build Protected Update Set tool"
cd ex_protected_update_data_set/Linux/
sudo make uninstall 
make clean 
make -j5 
sudo make install 
