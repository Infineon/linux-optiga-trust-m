#!/bin/bash
source config.sh


set -e

echo "Executing trustm_data commands"
echo "1234" >1234.txt
cat 1234.txt

echo "Writing text file 1234.txt into OID 0xE0E1 and reading after writing"
$EXEPATH/trustm_data -w 0xe0e1 -i 1234.txt
$EXEPATH/trustm_data -r 0xe0e1

echo "Erase with offset OID 0xE0E1"
$EXEPATH/trustm_data -w 0xe0e1 -e -p 10 -i 1234.txt
$EXEPATH/trustm_data -r 0xe0e1
