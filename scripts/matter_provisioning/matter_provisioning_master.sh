#!/bin/bash
source config.sh
source /etc/environment

# set -e

# This should be the master-script, which calls sub-scripts
# Input options
# Options: 
#    Provision DAC,PAI,CD from Test Setup
#    Provision DAC,PAI,CD from Bundle File
#    Supply Bundle File Transport Key
#    Disable Security Monitor (Bundle File required)
#    Internal only: Print QR Code for shield provisioning

test=0
bundle_file=0
transport_key=0
sec_config=0
qr=0

previous_chip_id="none"

while getopts tb:k:s:ih flag
do 
    case "${flag}" in
        t) test=1;;
        b) bundle_file=${OPTARG};;
        k) transport_key=${OPTARG};;
        s) sec_config=${OPTARG};;
        i) qr=1;;
        *) echo "Help! 
                -t Provision via Test-Setup
                -b [file] Input Bundle File
                -k [key] Transport-Key for Bundle File
                -s [config] Configure the Security Monitor with the input config
                -i INTERNAL ONLY: Additionally print QR Code
                -h Print this help" ;;
    esac
done

while sleep 1s;
do 
    chip_id=$($EXEPATH/trustm_probe)
    echo "Chip ID " $chip_id
    if [ -n "$chip_id" ]  && [ "$chip_id" != "$previous_chip_id" ]
    then
        ## while loop. check if different/any chip is connected in some way - e.g. via Chip-ID?
        previous_chip_id=$chip_id
        if [ $test -eq 1 ]
        then 
            echo "----> Flashing Test Credentials"
            ./matter_test_dac_provisioning.sh
            if [ $qr -eq 1 ]
            then
                echo "----> Printing QR-Code Sticker and adding to CSV-List"
                python3 ./print_sticker.py
            fi
        elif [ -s $bundle_file ]
        then
            ./matter_bundle_provisioning.sh $bundle_file $chip_id
        else 
            echo "Please make sure that the bundle file exists and is not empty!"
        fi

        if [ -n $sec_config ]
        then
            echo "here comes the fun part"
            ./configure_security_monitor.sh $bundle_file $chip_id $transport_key
        fi

    else 
        echo "Put a new Trust M"
    fi
done
