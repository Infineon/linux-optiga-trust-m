#!/bin/bash
source config.sh
source /etc/environment

matter_dac_file_tag=$MATTER_DAC_TAG$CERT_TAG
matter_pai_tag=$MATTER_PAI_TAG$CERT_TAG
pbs_filename="PBS_keys.txt"
auto_filename="auto_keys.txt"

show_help() {
    echo "Usage: 
                -p [directory] Path to Matter Credential Directory. This should contain the DACs and PAI as pem files.
                -k [directory] (optional) Path to Keys directory. This should contain the auto_keys.txt and PBS_keys.txt file.
                -c [ID] Chip ID of Trust M to provision
                -h Print this help"
}

set -e
path_to_credentials=''
path_to_keys=''
chip_id=0

while getopts p:c:k:h flag; do
    case "${flag}" in
    p) path_to_credentials=${OPTARG} ;;
    k) path_to_keys=${OPTARG} ;;
    c) chip_id=${OPTARG} ;;
    *)
        show_help
        exit
        ;;
    esac
done

if [ $OPTIND -eq 1 ]; then
    echo "No options were passed"
    show_help
    exit 1
fi

## Check if all input arguments exists and a matching DAC is found.
if [ ! -r "$path_to_credentials"/"$chip_id$matter_dac_file_tag" ]; then
    echo -e "${RED}No Matter DAC found for Chip ID $chip_id!${NC}"
    exit 1
fi
if [ ! -r "$path_to_credentials"/*"$matter_pai_tag" ]; then
    echo "$path_to_credentials"/*"$matter_pai_tag"
    echo -e "${RED}No Matter PAI found!${NC}"
    exit 1
fi
if [ -n "$path_to_keys" ]; then
    if [ ! -r "$path_to_keys"/"$pbs_filename" ]; then
        echo -e "${RED}No PBS File found in path: "$path_to_keys"/"$pbs_filename"${NC}"
        exit 1
    fi
    if [ ! -r "$path_to_keys"/"$auto_filename" ]; then
        echo -e "${RED}No Authorization Reference File found in path: "$path_to_keys"/"$auto_filename"${NC}"
        exit 1
    fi
    pbs=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_keys"/"$pbs_filename)
    auto=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_keys"/"$auto_filename)
fi

## PBS and AuthRef Keys are needed to provision DAC to E0E0. If none can be found in the file or the files have not been unpacked, try without.

if [ -z "$pbs" ]
then
    echo "No PBS found in file. Using default"
    PBS_COMMAND=''
else
    PBS_COMMAND="-P $pbs"
fi
if [ -z "$pbs" ]
then
    echo "No Auto found in file. Using default"
    AUTO_COMMAND=''
else 
    AUTO_COMMAND="-A $auto"
fi
## Do the actual writing

$EXEPATH/trustm_update_with_PBS_Auto -w $MATTER_DAC_LOC -c "$path_to_credentials"/"$chip_id$matter_dac_file_tag" $PBS_COMMAND $AUTO_COMMAND -e 1>${DEBUG_OUTPUT}
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Write DAC to $MATTER_DAC_LOC: Success ${NC}"
else 
    echo -e "${RED}Write DAC to $MATTER_DAC_LOC: Failure ${NC}"
    exit 1
fi

$EXEPATH/trustm_cert -w $MATTER_PAI_LOC -i "$path_to_credentials"/*"$matter_pai_tag" -X 1>${DEBUG_OUTPUT}
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Write PAI to $MATTER_PAI_LOC: Success ${NC}"
else 
    echo -e "${RED}Write PAI to $MATTER_PAI_LOC: Failure ${NC}"
    exit 1
fi
