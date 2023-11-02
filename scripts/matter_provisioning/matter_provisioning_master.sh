#!/bin/bash
source config.sh
source /etc/environment

show_help() {
    echo "Usage: 
                -t Provision via Test-Setup
                -b [file] Input Bundle File
                -k [key] Transport-Key for Bundle File
                -s [config] Configure the Security Monitor with the input config. If set to "0", the default config will be used. 
                -c [file] Provision Certificate Declaration to OPTIGA Trust M.
                -v Verify the late-stage provisioning. Will sign dummy data with the private key and verify with the DAC public key.
                -o Set the LcsO of objects to "operational" and Access Conditions.
                -h Print this help. See the ReadMe for more Info.

                Possible combinations:
                    -t                                      : Provision Matter Test Credentials
                    -b [FILE.7z] -k [KEY]                   : Provision Matter Credentials from Bundle File
                    -b [FILE.7z] -k [KEY] -o                : As above, additionally set the LcsO of provisioned objects to "operational" and Access Conditions
                    -b [FILE.7z] -k [KEY] -s [CONFIG]       : Provision Matter Credentials from Bundle File and Update Security Monitor with Config (0 or custom)
                    * -v                                    : Any of the above combination of arguments, but additionally verify private & public key config
                    * -o [CD.bin]                           : Provision Certificate Declaration to OPTIGA Trust M"
                    
}

# set -e

test=0
bundle_file_flag=0
bundle_file=0
transport_key_flag=0
transport_key=0
sec_flag=0
sec_config=$DEFAULT_SEC_CONFIG
operational=0
verify=0
cd_path=''
KEY_ARG=''
previous_chip_id="none"


## Input Arguments checking
while getopts tb:k:s:c:voh flag; do
    case "${flag}" in
    t) test=1 ;;
    b)  
        bundle_file_flag=1
        bundle_file=${OPTARG} ;;
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
    c) cd_path=${OPTARG} ;;
    o) operational=1 ;;
    v) verify=1 ;;
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

# if [ $bundle_file_flag -ne $transport_key_flag ]; then
#     echo "Bundle File supplied but no Transport Key or vice versa. Please check your arguments"
#     show_help
#     exit
# fi

## Extract necessary contents (DAC, PAI, Keys) from Bundle File
if [ -s $bundle_file ]; then
    echo "Bundle File Argument provided. Will extract the Matter Credentials to a temporary folder."
    7z x $bundle_file -otmp -y >/dev/null
    7z x tmp/*$MATTER_DAC_TAG's'$ZIP_TAG -otmp/matter_cred -y >/dev/null
    7z x tmp/*$MATTER_PAI_TAG$ZIP_TAG -otmp/matter_cred -y >/dev/null
    if [ $transport_key_flag -eq 1 ]; then
        echo "Transport Key Argument provided. Will extract the PBS and Auto Keys to a temporary folder."
        7z x tmp/*_keys.7z -p$transport_key -otmp/keys -y >/dev/null
        KEY_ARG="-k tmp/keys"
    fi
    rm tmp/*.7z tmp/README.txt
fi

## While loop. check if different/any chip is connected via Chip-Id
while sleep 1s; do
    chip_id=$($EXEPATH/trustm_probe)
    if [ $? -eq 0 ]
    then
        echo "Chip ID: " $chip_id
        # If a new Chip is connected, start the provisioning
        if [ -n "$chip_id" ] && [ "$chip_id" != "$previous_chip_id" ]; then
            previous_chip_id=$chip_id
            if [ $test -eq 1 ]; then
                echo "----> Flashing Test Credentials"
                ./matter_test_provisioning.sh
                if [ ! $? -eq 0 ]; then
                    continue
                fi
            fi
            if [ -s $bundle_file ]; then
                echo "----> Write Matter Credentials"
                ./matter_bundle_provisioning.sh -p tmp/matter_cred -c $chip_id $KEY_ARG
                if [ ! $? -eq 0 ]; then
                    continue
                fi 
                if [ $sec_flag -eq 1 ]; then
                    echo "----> Update Security Monitor"
                    ./configure_security_monitor.sh -p tmp/keys -c $chip_id -s $sec_config
                fi
            fi
            if [ -n "$cd_path" ] && [ -s $cd_path ]; then
                echo "----> Write Matter CD into "$MATTER_CD_LOC
                $EXEPATH/trustm_data -e -w $MATTER_CD_LOC -i "$cd_path" -X 1>${DEBUG_OUTPUT}
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Write CD to $MATTER_CD_LOC: Success ${NC}"
                else 
                    echo -e "${RED}Write CD to $MATTER_CD_LOC: Failure ${NC}"
                    exit 1
                fi
            fi
            if [ $verify -eq 1 ]; then
                echo "----> Testing DAC & Private Key"
                ./verify_configuration.sh
                if [ ! $? -eq 0 ]; then
                    continue
                fi 
            fi
            if [ $operational -eq 1 ]; then
                echo "----> Set AC and LcsO."
                ## E0E0 SHALL be set to operational, 
                ## PAI and CD (if used) SHALL be set to operational and the CHA AC SHALL be set to PBS and AUTO 
                echo "First time usage. To prevent accidental errors, the following lines were commented out"
                ## Uncomment the following lines to set the operational metadata of the chip
                # $EXEPATH/trustm_metadata -w $MATTER_DAC_LOC -O -X
                # $EXEPATH/trustm_metadata -w $MATTER_PAI_LOC -F test_files/meta_pbs_auto.bin -O -X
                # $EXEPATH/trustm_metadata -w $MATTER_CD_LOC -F test_files/meta_pbs_auto.bin -O -X
            fi
        else
            echo "Put a new Trust M or press Ctrl+C to exit"
        fi
    else 
        echo "Could not open Trust M"
    fi
done
rm -rf ./tmp
