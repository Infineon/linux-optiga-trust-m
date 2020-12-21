#!/bin/bash
source config.sh

sudo rm *.csr
sudo rm *.pem

set -e

for i in $(seq 1 5); do
echo "test $i"

echo "Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request by openssl using linux driver"
sudo openssl req -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out client1_e0f1.csr -subj /CN=Client1
sudo openssl req -in client1_e0f1.csr -text

sleep 1
done
