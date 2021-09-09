#!/bin/bash
source config.sh

set -e
echo "Copy simpleTest executable into current directory"
cp $EXEPATH/simpleTest* $PWD/
