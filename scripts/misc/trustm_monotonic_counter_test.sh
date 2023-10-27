#!/bin/bash
source config.sh


set -e

echo "Executing trustm_monotonic_counter commands"
echo "Setting threshold value to 10 and reset counter to zero"
$EXEPATH/trustm_monotonic_counter -w 0xe120 -i 10

echo "Count up monotonic counter in steps of 2"
$EXEPATH/trustm_monotonic_counter -u 0xe120 -s 2
$EXEPATH/trustm_monotonic_counter -r 0xe120
