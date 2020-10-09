#!/bin/bash
source config.sh

rm *.dat
echo "Generate default shared secret"

set -e
$EXEPATH/trustm_data -X -r  0xe140
echo "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40" | xxd -r -p > binary.dat
xxd binary.dat
$EXEPATH/trustm_data -X -w 0xe140 -i binary.dat
$EXEPATH/trustm_data -X -r  0xe140
