# Integrity and Confidentiality Protected Update for AES key 

The following example shows how to do Integrity and Confidentiality Protected Update for AES key.

This folder provides a simplified flow with ready-to-run scripts:

- Step 1: Provision trust anchor + protected update secret + configure target AES key metadata for protected update
- Step 2: Generate the manifest and the fragment for the AES key update (payload version is auto-incremented)
- Step 3: Perform the protected update using the generated manifest/fragment

Note: OIDs, file paths, algorithms for AES Protected Update and metadata settings can be configured in "**config.sh**".


## 1. Step 1:  Provisioning (Trust Anchor, Protected Update Secret, Target AES key OID)

Run Script: "**step1_protected_update_aes_provisioning.sh**"

### 1.1 Write Trust Anchor into a data object and change the data object type to TA

In "**config.sh**", OID `0xE0E8` is used as Trust Anchor in this example:

```
TRUST_ANCHOR_OID="e0e8"
TRUST_ANCHOR_CERT="$CERT_PATH/sample_ec_256_cert.pem"
TRUST_ANCHOR_META="2003E80111"
```

This script:
- Writes `sample_ec_256_cert.pem` into `0xE0E8` using as Trust Anchor

- Writes `TRUST_ANCHOR_META` to `0xE0E8` to set the data object type to TA (Trust Anchor)

  Note: OPTIGA™ Trust M provides two dedicated slots for storing trust anchor certificates: 0xE0E8 and 0xE0E9.

### 1.2 Write Protected Update Secret into a data object and change the data object type to UPDATSEC

In "**config.sh**", OID `0xF1D4` is used as Protected Update Secret:

```
PROTECTED_UPDATE_SECRET_OID="f1d4"
PROTECTED_UPDATE_SECRET="$SECRETPATH/secret.txt"
PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"
```

This script:
- Writes the secret into `0xF1D4` as Protected Update Secret

- Writes `PROTECTED_UPDATE_SECRET_META` to 0xF1D4 to set the data object type to UPDATSEC (Protected Update Secret)

  Note: The OID for Protected Update Secret can be chose from 0xF1D4 to 0xF1DB.

### 1.3 Configure metadata of the target AES key OID for protected update

In "**config.sh**", OID `0xE200` is used as the target AES key object:

```
TARGET_AES_OID="e200"
TARGET_AES_OID_META="200dC1020000D00721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"
```

This script writes this metadata to `0xE200` using `trustm_metadata`.

What this achieves:
- Sets the payload version field (`C1 ...`) to `0000`
- Sets the change access condition for AES key Protected Update:
  - Integrity protection using the configured Trust Anchor OID
  - Confidentiality protection using the configured Protected Update Secret OID

For detailed data object type and metadata definitions, please refer to the  [OPTIGA Trust M Solution Reference Manual](https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md).

---

## 2. Step 2: Generate manifest and fragment for AES key update

Run Script: "**step2_generate_manifest.sh**"

This script does the following:

1. Reads metadata from the target AES key OID (`0xE200`)

2. Extracts the current payload version from the metadata output

3. Increments payload version

   Note: Protected Update requires a monotonically increasing payload version. 

   In this test scripts:

   The payload version is automatically incremented by 1 for each new manifest + fragment pair that is generated.

   If the payload version reaches the maximum limit, the script prints a warning message

   To reset the payload version, please use `step0_reset_payload_version.sh`

4. Generates manifest and fragment for AES key protected update 

These two files are required for Step 3.


## 3. Step 3: Perform Protected Update for AES key 

Run Script: "**step3_protected_update_aes.sh**"

This script performs the protected update using:

```
./trustm_protected_update_aeskey -k 0xE200 -f aes_fragment.dat -m aes_manifest.dat
```

If the protected update is successful, the AES key inside `0xE200` will be updated and the payload version in the object metadata will be updated to the new version used in Step 2.

---

## Optional helpers

### Reset payload version

Run Script: "**step0_reset_payload_version.sh**"

If the payload version reaches the maximum limit, you can reset the payload version field in the target OID metadata.

### Reset target OID metadata

Run Script: "**step0_reset_targetOID_metadata.sh**"

Resets the change access condition and payload version for target AES key OID.

### Clean all the temporary files in the folder

Run Script: "**cleanfiles.sh**" to clean all the temporary files in the folder.

---

## How to run

Run the test scripts inside folder following the sequency: "**linux-optiga-trust-m/scripts/protected_update_aeskey/**":

```
# Step 1: Provisioning (usually one-time per device)
./step1_protected_update_aes_provisioning.sh

# Step 2: Generate manifest + fragment
./step2_generate_manifest.sh

# Step 3: Perform protected update
./step3_protected_update_aes.sh
```



