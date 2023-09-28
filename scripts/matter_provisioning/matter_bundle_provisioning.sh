#!/bin/bash
source config.sh
source /etc/environment

matter_dac_tag=$MATTER_DAC_TAG
matter_pai_tag=$MATTER_PAI_TAG
matter_cd_tag=$MATTER_CD_TAG
pbs_filename="PBS_keys.txt"
auto_filename="auto_keys.txt"

show_help() {
    echo "Usage: 
                -p [directory] Path to Matter Credential Directory. This should contain the DAC, PAI and CD.
                -k [directory] Path to Keys directory. This should contain the auto_keys.txt and PBS_keys.txt file.
                -c [ID] Chip ID of Trust M to provision
                -h Print this help"
}

set -e
path_to_credentials=0
path_to_keys=0
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
    exit
fi

if [ ! -r "$path_to_credentials"/"$chip_id$matter_dac_tag" ]; then
    echo "No Matter DAC found!"
    exit
fi
if [ ! -r "$path_to_credentials"/*"$matter_pai_tag" ]; then
    echo "$path_to_credentials"/*"$matter_pai_tag"
    echo "No Matter PAI found!"
    exit
fi
if [ ! -r "$path_to_credentials"/*"$matter_cd_tag" ]; then
    echo "No Matter CD found!"
    exit
fi
if [ ! -r "$path_to_keys"/"$pbs_filename" ]; then
    echo "No PBS File found in path: "$path_to_keys"/"$pbs_filename
    exit
fi
if [ ! -r "$path_to_keys"/"$auto_filename" ]; then
    echo "No Authorization Reference File found in path: "$path_to_keys"/"$auto_filename
    exit
fi

pbs=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_keys"/"$pbs_filename)
auto=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_keys"/"$auto_filename)

echo "-----> Write Matter DAC into "$MATTER_DAC_LOC  
$EXEPATH/trustm_update_with_PBS_Auto -w $MATTER_DAC_LOC -c "$path_to_credentials"/"$chip_id$matter_dac_tag" -P $pbs -A $auto -e
echo "-----> DAC display"
openssl x509 -in "$path_to_credentials"/"$chip_id$matter_dac_tag" -text -noout
echo "-----> Write Matter PAI into "$MATTER_PAI_LOC
$EXEPATH/trustm_cert -w $MATTER_PAI_LOC -i "$path_to_credentials"/*"$matter_pai_tag" -X
echo "-----> Write Matter CD into "$MATTER_CD_LOC
$EXEPATH/trustm_data -e -w $MATTER_CD_LOC -i "$path_to_credentials"/*"$matter_cd_tag" -X
