#!/bin/bash
source config.sh

#### Configurable Variables Start

## Target OID for metadata protected update, manifest and final fragment
# Target OID
TARGET_OID=f1d6
# Manifest used for metadata protected update (To Creation)
MANIFEST="8443A10126A10442E0E8589B8601F6F684210D038200008282205825821829582055C9E24B593CB489AEBD3B2CF1EDB386467996C45302154D4BAFDCC2123C08E482018343A1010A81825854A30442F1D4013A000100B705824474657374584029360E0052C5A60119FD8D3917734F76CF2214189488E713455167E6A7BDE02A72F70C6CDCAB5AE0061A4CB02A8E971B4EABE2880A60C6B49AFCAB8812B9316AF6F6824042F1D658409956E60983CEF3A82D171421F2F18EC66C31EE5146B77B91C93924EBC4715168A074567919B7196C8EF69BE2A77B53E0EDE82928C7B764BC78E431A6F7CE196C"
FINAL_FRAGMENT="3352E83CD53EC179F4A41DAC7BF1A7AB29391F2D06"


#### Configurable Variables End

# Perform multiple sequential read
echo "Prepare binary shared secret."
echo $MANIFEST | xxd -r -p > manifest.dat
#~ xxd manifest.dat
echo "Prepare binary data to be init."
echo $FINAL_FRAGMENT | xxd -r -p > final_fragment.dat
#~ xxd final_fragment.dat

for i in $(seq 1 1); do
echo "test $i"

echo "Metadata protected update for 0x$TARGET_OID"
$EXEPATH/trustm_protected_update -k 0x$TARGET_OID -m manifest.dat -f final_fragment.dat
echo "read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID -X



sleep 1
done
