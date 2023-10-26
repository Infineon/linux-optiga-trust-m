#!/bin/bash
source config.sh

# Perform multiple sequential read
for i in $(seq 1 100); do
echo "test $i"

$EXEPATH/trustm_data -X -r  0xe0c5
#~ $EXEPATH/trustm_data  -r  0xe0c5   # un-remark this section to increase the security counter every read action.

sleep 1
done
