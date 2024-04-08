#!/bin/bash

rm -d -r -f  demoCA*

rm *.csr
rm *.pem

mkdir demoCA
cd demoCA
touch index.txt
mkdir private
mkdir newcerts
