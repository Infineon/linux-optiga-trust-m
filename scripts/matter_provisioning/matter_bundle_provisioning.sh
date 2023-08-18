#!/bin/bash
source config.sh
source /etc/environment

matter_dac_tag="_E0E0.pem"
matter_pai_tag="PAI-noPID-Cert.pem"
matter_cd_tag="CD-Cert.bin"

show_help()
{
    echo "Usage: 
                -p [directory] Path to Matter Credential Directory. This should contain the DAC, PAI and CD.
                -c [ID] Chip ID of Trust M to provision
                -h Print this help"
}

set -e
path_to_credentials=0
chip_id=0

while getopts p:c:h flag
do 
    case "${flag}" in
        p) path_to_credentials=${OPTARG};;
        c) chip_id=${OPTARG};;
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

if [ ! -r "$path_to_credentials"/"$chip_id$matter_dac_tag" ]
then
    echo "No Matter DAC found!"
    exit
fi
if [ ! -r "$path_to_credentials"/*"$matter_pai_tag" ]
then
    echo "$path_to_credentials"/*"$matter_pai_tag"
    echo "No Matter PAI found!"
    exit
fi
if [ ! -r "$path_to_credentials"/*"$matter_cd_tag" ]
then
    echo "No Matter CD found!"
    exit
fi

echo "-----> Write Matter DAC into 0xe0e3"
$EXEPATH/trustm_cert -w 0xe0e3 -i "$path_to_credentials"/"$chip_id$matter_dac_tag" -X
echo "-----> DAC display"
openssl x509 -in "$path_to_credentials"/"$chip_id$matter_dac_tag" -text -noout
echo "-----> Write Matter PAI into 0xe0e8"
$EXEPATH/trustm_cert -w 0xe0e8 -i "$path_to_credentials"/*"$matter_pai_tag" -X
echo "-----> Write Matter CD into 0xf1e0"
$EXEPATH/trustm_data -e -w 0xf1e0 -i "$path_to_credentials"/*"$matter_cd_tag" -X