#set this EXEPATH to the location that store the executable binary
EXEPATH="/home/pi/Desktop/WIP1/TrustM/cli-optiga-trust-m/bin"

# Perform multiple sequential read
for i in $(seq 1 1000); do
echo "test $i"
$EXEPATH/trustm_data -X -r  0xe0c5
#~ $EXEPATH/trustm_data  -r  0xe0c5   # un-remark this section to increase the security counter every read action.
done
