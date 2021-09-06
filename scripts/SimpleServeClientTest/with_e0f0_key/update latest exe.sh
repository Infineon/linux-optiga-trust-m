#!/bin/bash
source config.sh

rm simpleTest*

#~ ls $EXEPATH/simpleTest*
cp $EXEPATH/simpleTest* $PWD/
$EXEPATH/trustm_cert -r 0xe0e0 -o test_e0e0.crt


