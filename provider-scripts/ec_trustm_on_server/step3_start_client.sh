#!/bin/bash
source config.sh

echo "-----> Running the test client1"
lxterminal -e openssl s_client -connect localhost:5000 -servername Server1 -cert client.crt -key privkey.pem -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem
