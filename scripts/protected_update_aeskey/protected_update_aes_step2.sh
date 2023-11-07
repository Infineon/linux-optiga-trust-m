#!/bin/bash
source config.sh

#### Configurable Variables Start

## Target OID for AES key protected update, manifest and final fragment
# Target OID
TARGET_OID=e200

# Sample Manifest used for AES Key protected update 
# Sample Manifest and Fragment int-E0E8, Conf-F1D4, Ver=03, Target OID = E0E1 used for AES Key protected update 
MANIFEST="8443A10126A10442E0E8589C8601F6F6842213038218810282822058258218295820059D47FADDFDDA98C3C5C91BF2A8E6382E429C0CC2430E1BEC5A52444F960D5F82018343A1010A81825854A30442F1D4013A000100B70582447465737458406DA9A81418E337C455607E4B8FDBE270BAD79276618CB3D112CB4E3AD24863F82E888BCDF33460D4A6940D11B3C23593C8C0C408EA7EA5487B77D7E903291FFAF6F6824042E2005840FFD3E51737F13C667D711D45307888D798B45050839FE4406DDA068B50D2CA51FC740ADC7EB754FC72E6790C006A71D3B77A62A25C8B34801475EC477831950E"
FINAL_FRAGMENT="35629F228594CC0B2AD9523E640849A9272F276280CE3FEB529DC3"

#### Configurable Variables End

# Perform multiple sequential read
echo "Prepare binary shared secret."
echo $MANIFEST | xxd -r -p > manifest_aes.dat
#~ xxd manifest.dat
echo "Prepare binary data to be init."
echo $FINAL_FRAGMENT | xxd -r -p > final_fragment_aes.dat
#~ xxd final_fragment.dat

for i in $(seq 1 1); do
echo "test $i"

echo "Protected AES Key Update for 0x$TARGET_OID"
$EXEPATH/trustm_protected_update_aeskey -k 0x$TARGET_OID -m manifest_aes.dat -f final_fragment_aes.dat
echo "read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID -X



sleep 1
done
