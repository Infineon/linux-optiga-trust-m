#!/bin/bash
source config.sh

# Perform multiple sequential read

echo "Print out manifest."
echo "8443A10126A10442E0E3583B8601F6F684210D03820000828220582582182958201267B0CCD50244E5B59386B5D3943B853F1A3FAB4727C79E19A4642B2A985A2DF6824042E1405840E9E10C1BDB5251CAE8D35D45FC964EEE8D6825C4FC0D740FE29064A0C8054FAD43D47CE2A36235E1E999974F04183B15E59429CA2BC864B041DC9D5D327FD2DF" | xxd -r -p > manifest_e140_p3_i.dat
xxd manifest_e140_p3_i.dat
echo "Print out final fragment."
echo "200BC00101D10100D003E1FC07" | xxd -r -p > fragment_e140_p3_i.dat
xxd fragment_e140_p3_i.dat

for i in $(seq 1 1); do
echo "test $i"


echo "Metadata protected update for E140"
$EXEPATH/trustm_protected_update -k 0xe140 -m manifest_e140_p3_i.dat -f fragment_e140_p3_i.dat
echo "read out metadata for 0xE140"
$EXEPATH/trustm_metadata -r  0xe140 -X

#~ echo "Reset version tag for 0xE140(For testing Purpose)"
#~ echo "Write metadata for 0xE140"
#~ echo -e -n \\x20\\x04\\xC1\\x02\\x00\\x00 >version_reset.bin
#~ xxd version_reset.bin
#~ $EXEPATH/trustm_metadata -w 0xe140 -F version_reset.bin
#~ echo "read out metadata for 0xE140"
#~ $EXEPATH/trustm_metadata -r  0xe140 



sleep 1
done
