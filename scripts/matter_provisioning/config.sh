PROJECT_DIR=$(dirname "$(dirname "$(pwd)")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"

## Console ANSI Color Schemes
RED='\033[0;31m'
GREEN='\033[0;92m'
NC='\033[0m' # No Color

## Trust M OIDs, Location of Data Objects to be provisioned
MATTER_DAC_LOC=0xE0E0
MATTER_PAI_LOC=0xE0E8
MATTER_CD_LOC=0xF1E0

DEFAULT_SEC_CONFIG="000050100000000"
DEFAULT_METADATA=""

## Bundle File Structure
MATTER_DAC_TAG="_keyOID=E0F0_DAC"
MATTER_PAI_TAG="keyOID=E0F0_PAI"
KEYS_TAG="_keys"
CERT_TAG=".pem"
ZIP_TAG=".7z"


## If you want to see the output logs, replace /dev/null with /dev/stdout
DEBUG_OUTPUT="/dev/null"