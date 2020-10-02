#set this EXEPATH to the location that store the executable binary
EXEPATH="/home/pi/Desktop/WIP1/TrustM/cli-optiga-trust-m/bin"

#for multiple process access test 
for i in $(seq 1 8); do
echo "test $i"
openssl rand -engine trustm_engine -base64 256 &
$EXEPATH/trustm_data -X -r  0xe0c5 &
done
