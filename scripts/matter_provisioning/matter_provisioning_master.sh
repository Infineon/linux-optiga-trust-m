#!/bin/bash
source config.sh
source /etc/environment

show_help()
{
    echo "Usage 
                -t Provision via Test-Setup
                -b [file] Input Bundle File
                -k [key] Transport-Key for Bundle File
                -s [config] Configure the Security Monitor with the input config. If set to "0", the default config will be used. 
                -i INTERNAL ONLY: Additionally print QR Code
                -h Print this help
                Possible combinations:
                    -t                      	        : Provision Matter Test Credentials
                    -t -i                               : Provision Matter Test Credentials and print QR Code
                    -b [FILE.7z]                        : Provision Matter Credentials from Bundle File
                    -b [FILE.7z] -t [KEY] -s [CONFIG]   : Provision Matter Credentials from Bundle File and Update Security Monitor with Config" 
                    
}

set -e

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
sec_flag=0
sec_config="000050100000000"
qr=0

previous_chip_id="none"

while getopts tb:k:s:ih flag
do 
    case "${flag}" in
        t) test=1;;
        b) bundle_file=${OPTARG};;
        k) transport_key=${OPTARG};;
        s) sec_flag=1
            if [ ! 0 == ${OPTARG} ]
            then
            sec_config=${OPTARG}
            fi;;
        i) qr=1;;
        *) show_help
            exit;;
    esac
done

if [ $OPTIND -eq 1 ]; 
then 
    echo "No options were passed";
    show_help
    exit
fi

if [ -s $bundle_file ]
then
    echo "Bundle File Argument provided. Will extract the Matter Credentials to a temporary folder."
    7z x $bundle_file -otmp -y > /dev/null
    7z x tmp/*_E0E0_Certs.7z -otmp/matter_cred -y > /dev/null
    if [ -n "$transport_key" ]
    then 
        echo "Transport Key Argument provided. Will extract the PBS and Auto Keys to a temporary folder."
        7z x tmp/*_keys.7z -p$transport_key -otmp/keys -y > /dev/null
    fi
    rm tmp/*.7z tmp/README.txt
fi

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
            echo "----> Write Matter Credentials"
            ./matter_bundle_provisioning.sh -p tmp/matter_cred -c $chip_id
            if [ -n "$sec_config" ]
            then
                echo "----> Update Security Monitor"
                ./configure_security_monitor.sh -p tmp/keys -c $chip_id -s $sec_config
            fi
        else 
            echo "Please input a valid Configuration or make sure that the bundle file exists!"
            show_help
            break;
        fi
    else 
        echo "Put a new Trust M or press Ctrl+C to exit"
    fi
done
rm -rf ./tmp