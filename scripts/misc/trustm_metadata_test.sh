#!/bin/bash
source config.sh


set -e

echo "Executing trustm_metadata commands"
echo "Changing OID 0xE0E1 metadata to read only and reading the metadata"
$EXEPATH/trustm_metadata -w 0xe0e1 -Cn -Ra
$EXEPATH/trustm_metadata -r 0xe0e1

echo "changing OID 0xE0E1 metadata using complex setting (LcsO>3||LcsG<4) for Change mode"
echo -e -n \\x07\\xe1\\xfb\\x03\\xfe\\x70\\xfc\\x04 > complexsetting.bin
hd complexsetting.bin 
$EXEPATH/trustm_metadata -w 0xe0e1 -Cf:complexsetting.bin
$EXEPATH/trustm_metadata -r 0xe0e1
