#!/bin/bash
source config.sh
source /etc/environment

show_help() {
    echo "Usage: 
                -t Provision via Test-Setup
                -b [file] Input Bundle File
                -k [key] Transport-Key for Bundle File
                -s [config] Configure the Security Monitor with the input config. If set to "0", the default config will be used. 
                -i INTERNAL ONLY: Additionally print QR Code
                -o Set the LcsO of objects to "operational" and Access Conditions.
                -h Print this help. See the ReadMe for more Info.
                Possible combinations:
                    -t                      	            : Provision Matter Test Credentials
                    -t -i                                   : Provision Matter Test Credentials and print QR Code
                    -b [FILE.7z]                            : Provision Matter Credentials from Bundle File
                    -b [FILE.7z] -t [KEY] -s [CONFIG]       : Provision Matter Credentials from Bundle File and Update Security Monitor with Config (0 or custom)
                    -b [FILE.7z] -t [KEY] -s [CONFIG] -o    : As above, additionally set the LcsO of provisioned objects to "operational" and Access Conditions"

}

set -e

test=0
bundle_file=0
transport_key_flag=0
transport_key=0
sec_flag=0
sec_config=$DEFAULT_SEC_CONFIG
operational=0
qr=0

previous_chip_id="none"

while getopts tb:k:s:ioh flag; do
    case "${flag}" in
    t) test=1 ;;
    b) bundle_file=${OPTARG} ;;
    k)
        transport_key_flag=1
        transport_key=${OPTARG}
        ;;
    s)
        sec_flag=1
        if [ ! 0 == ${OPTARG} ]; then
            sec_config=${OPTARG}
        fi
        ;;
    i) qr=1 ;;
    o) operational=1 ;;
    *)
        show_help
        exit
        ;;
    esac
done

if [ $OPTIND -eq 1 ]; then
    echo "No options were passed"
    show_help
    exit
fi

if [ $sec_flag -ne $transport_key_flag ]; then
    echo "Security Configuration supplied but no Transport Key or vice versa. Please check your arguments"
    show_help
    exit
fi

if [ -s $bundle_file ]; then
    echo "Bundle File Argument provided. Will extract the Matter Credentials to a temporary folder."
    7z x $bundle_file -otmp -y >/dev/null
    7z x tmp/*_E0E0_Certs.7z -otmp/matter_cred -y >/dev/null
    if [ $transport_key_flag -eq 1 ]; then
        echo "Transport Key Argument provided. Will extract the PBS and Auto Keys to a temporary folder."
        7z x tmp/*_keys.7z -p$transport_key -otmp/keys -y >/dev/null
    fi
    rm tmp/*.7z tmp/README.txt
fi

## While loop. check if different/any chip is connected via Chip-Id
while sleep 1s; do
    chip_id=$($EXEPATH/trustm_probe)
    echo "Chip ID: " $chip_id
    if [ -n "$chip_id" ] && [ "$chip_id" != "$previous_chip_id" ]; then
        previous_chip_id=$chip_id
        if [ $test -eq 1 ]; then
            echo "----> Flashing Test Credentials"
            ./matter_test_provisioning.sh
            if [ $qr -eq 1 ]; then
                echo "----> Internal Provisioning"
                # python3 ./print_sticker.py
            fi
        elif [ -s $bundle_file ]; then
            echo "----> Write Matter Credentials"
            ./matter_bundle_provisioning.sh -p tmp/matter_cred -c $chip_id
            if [ $sec_flag -eq 1 ]; then
                echo "----> Update Security Monitor"
                ./configure_security_monitor.sh -p tmp/keys -c $chip_id -s $sec_config
            fi
            if [ $operational -eq 1 ]; then
                echo "----> Set AC and LcsO."
                # $EXEPATH/trustm_metadata -w $MATTER_DAC_LOC -F meta_pbs_auto.bin -O -X
                # $EXEPATH/trustm_metadata -w $MATTER_PAI_LOC -F meta_pbs_auto.bin -O -X
                # $EXEPATH/trustm_metadata -w $MATTER_CD_TAG -F meta_pbs_auto.bin -O -X
                # $EXEPATH/trustm_metadata -w 0xE0E0 -T -X
            fi
        else
            echo "Please input a valid Configuration or make sure that the bundle file exists!"
            show_help
            break
        fi
    else
        echo "Put a new Trust M or press Ctrl+C to exit"
    fi
done
rm -rf ./tmp
