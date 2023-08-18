#!/bin/bash
source config.sh
source /etc/environment

pbs_filename="PBS_keys.txt"
auto_filename="auto_keys.txt"

show_help()
{
    echo "Usage: 
                -p [directory] Path to Keys directory. This should contain the auto_keys.txt and PBS_keys.txt file.
                -c [ID] Chip ID of Trust M to provision
                -s [config] (optional) Configure the Security Monitor with the input config instead of the default (off) configuration.
                -h Print this help"
}


path_to_credentials=0
chip_id=0
sec_config="000050100000000"

while getopts p:c:s:h flag
do 
    case "${flag}" in
        p) path_to_credentials=${OPTARG};;
        c) chip_id=${OPTARG};;
        s) sec_config=${OPTARG};;
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

if [ ! -r "$path_to_credentials"/"$pbs_filename" ]
then
    echo "No PBS File found in path: "$path_to_credentials"/"$pbs_filename
    exit
fi
if [ ! -r "$path_to_credentials"/"$auto_filename" ]
then
    echo "No Authorization Reference File found in path: "$path_to_credentials"/"$auto_filename
    exit
fi

pbs=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_credentials"/"$pbs_filename)
auto=$(awk -F, -v c=$chip_id '$1==c {print $2}' $path_to_credentials"/"$auto_filename)

echo "PBS:" $pbs 
echo "Auto:" $auto

echo "-----> Update Security Monitor Configuration in 0xE0C9"
$EXEPATH/trustm_update_with_PBS_Auto -w 0xe0c9 -P $pbs -A $auto -I $sec_config