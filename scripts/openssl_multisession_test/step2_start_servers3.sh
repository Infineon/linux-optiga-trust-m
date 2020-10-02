EXEPATH="../bin"
CERT_PATH="/home/pi/Desktop/WIP1/TrustM/cli-optiga-trust-m/trustm_lib/certificates"


#~ echo "-----> Running the test server1"
#~ openssl s_server -cert server1.crt -key server1_privkey.pem -accept 5000 -verify_return_error -Verify 1 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem 

#~ echo "-----> Running the test server2"
#~ openssl s_server -cert server2.crt -key server2_privkey.pem -accept 5001 -verify_return_error -Verify 1 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem &

echo "-----> Running the test server3"
openssl s_server -cert server3.crt -key server3_privkey.pem -accept 5002 -verify_return_error -Verify 1 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem 
