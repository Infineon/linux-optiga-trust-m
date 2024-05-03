#!/bin/bash
set -exo pipefail

# generate RSA 2048 key in 0xE0FD (key usage auth/enc/sign) and extract public key file
# 0xe0fd is TrustM RSA Key id
# The generated public key is stored in the e0fd_pub.pem file
openssl pkey -provider trustm_provider -in 0xe0fd:*:NEW:0x42:0x13 -pubout -out e0fd_pub.pem

#the public key is generated and stored in the file
#sender sends the message with a digital signature
#the digital signature is the hashed message that has been encrypted by the RSA key
#to verify the message, the recipient uses the sender's public key to decrypt it.
#if the decrypted value is the same as the hashed message received then it is successfully verified
