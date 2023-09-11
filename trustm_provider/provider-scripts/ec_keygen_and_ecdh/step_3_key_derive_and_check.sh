#!/bin/bash
set -eufx pipefail


# alice derives shared secret using Trust M API, bob's public key and alice's private key in Trust M
openssl pkeyutl -provider trustm_provider -provider default -derive -inkey 0xe0f2:^ -peerkey testkey2.pub -out secret1.key

echo Alice derived key:
hd secret1.key

# bob derives shared secret using OpenSSL and alice's public key
openssl pkeyutl -derive -inkey testkey2.priv -peerkey testkey1.pub -out secret2.key

echo Bob derived key:
hd secret2.key

# the secrets should be identical
diff -s secret1.key secret2.key

rm testkey1.pub testkey2.pub testkey2.priv secret1.key secret2.key