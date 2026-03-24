# Integrity and Confidentiality Protected Update for metadata 

The following example shows how to do Integrity and Confidentiality Protected Update for metadata. 

This folder provides a simplified flow with ready-to-run scripts:

\- Step 1: Provision trust anchor + protected update secret + configure target OID metadata for protected update  

\- Step 2: Generate the manifest and the fragment for the metadata protected update (payload version is auto-incremented)  

\- Step 3: Perform the protected update using the generated manifest/fragment

Note: OIDs, file paths, algorithms for metadata Protected Update and metadata settings can be configured in "***\*config.sh\****".

## 1. Step 1: Provisioning (Trust Anchor, Protected Update Secret, Target OID)

Run Script: "**step1_protected_update_metadata_provisioning.sh**"

### 1.1 Write Trust Anchor into a data object and change the data object type to TA

In "**config.sh**", OID `0xE0E8` is used as Trust Anchor in this example:

```
TRUST_ANCHOR_OID="e0e8"
TRUST_ANCHOR_CERT="$CERT_PATH/sample_ec_256_cert.pem"
TRUST_ANCHOR_META="2003E80111"
```

This script:
- Writes `sample_ec_256_cert.pem` into `0xE0E8` as Trust Anchor (via `trustm_cert`)
- Writes `TRUST_ANCHOR_META` to `0xE0E8` to set the data object type to TA (Trust Anchor)  
  Note: OPTIGA™ Trust M provides two dedicated slots for storing trust anchor certificates: `0xE0E8` and `0xE0E9`.

E8 means data object Type, the following "01" means the length of the coming data, and the last"11" means Trust Anchor type.

After running  "**step1_protected_update_metadata_provisioning.sh**", the data object type is set to Trust Anchor. 

```console
foo@bar:~$ ./bin/trustm_metadata -r 0xe0e8
========================================================
Root CA Public Key Cert1    [0xE0E8] 
[Size 0027] : 
	20 19 C0 01 01 C4 02 04 B0 C5 02 02 5C D0 03 E1 
	FC 07 D1 01 00 D3 01 00 E8 01 11 
	LcsO:0x01, Max Size:1200, Used Size:604, Change:LcsO<0x07, Read:ALW, Execute:ALW, Data Type:TA, 

========================================================
```

For detailed data object type, metadata associated with data and key objects, please refer to [OPTIGA_Trust_M_Solution_Reference_Manual](https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md) 

### 1.2 Write Protected Update Secret into a data object and change the data object type to UPDATSEC

In "**config.sh**", OID `0xF1D4` is used as Protected Update Secret:

```
PROTECTED_UPDATE_SECRET_OID="f1d4"
PROTECTED_UPDATE_SECRET="$SECRETPATH/secret.txt"
PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"
```

This script:
- Writes the secret into `0xF1D4` as Protected Update Secret
- Writes `PROTECTED_UPDATE_SECRET_META` to `0xF1D4` to set the data object type to UPDATSEC (Protected Update Secret)  
  Note: The OID for Protected Update Secret can be chosen from `0xF1D4` to `0xF1DB`.

E8 means data object Type, the following "01" means the length of the coming data, and the last"23" means Protected Update Secret type.

After running  "**step1_protected_update_metadata_provisioning.sh**", the data object type is set to Protected Update Secret. 

```console
foo@bar:~$ ./bin/trustm_metadata -r 0xf1d4
App DataStrucObj type 3     [0xF1D4] 
[Size 0027] : 
	20 19 C0 01 01 C4 01 8C C5 01 40 D0 03 E1 FC 07 
	D1 03 E1 FC 07 D3 01 00 E8 01 23 
	LcsO:0x01, Max Size:140, Used Size:64, Change:LcsO<0x07, Read:LcsO<0x07, Execute:ALW, Data Type:UPDATSEC, 
```

For detailed data object type, metadata associated with data and key objects, please refer to [OPTIGA_Trust_M_Solution_Reference_Manual](https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md)  

### **1.3 Configure metadata of the target OID for protected update**

In "**config.sh**", OID `0xF1D6` is used as the target OID:

1. Configure the metadata of the target data object and change the metadata of the target OID accordingly.
  In "**config.sh**", the data object `0xF1D6` is used as the target OID for metadata protected update:

    ```console
    TARGET_OID="f1d6"
    TARGET_OID_META="2010C1020000F00111D80721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"
    ```

  C1 means the version number, the following "02" means the length of the coming data, and the following"0000" the means version number is "0000".

  F0 means Reset type, the following "01" means the length of the coming data, and the following"11" means bring back to creation state and flush the data inside.

  D8 means metadata Update descriptor, this  tag  defines  the  condition  under  which  the  metadata update is permitted. The following "07" means the length of the coming data."21" means integrity protection," $TRUST_ANCHOR_OID" is the OID used to store Trust Anchor,"20" means confidentiality protection,"${PROTECTED_UPDATE_SECRET_OID}"is the OID used to store Protected Update Secret.

  This script writes this metadata to `0x$TARGET_OID`.

  What this achieves:
  - Sets the payload version field (`C1 ...`) to `0000`
  - Sets the MUD for metadata Protected Update:
    - Integrity protection using the configured Trust Anchor OID
    - Confidentiality protection using the configured Protected Update Secret OID

  For detailed metadata associated with data and key objects, please refer to [OPTIGA_Trust_M_Solution_Reference_Manual](https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md)  

  After running  "**step1_protected_update_metadata_provisioning.sh**", the metadata of target OID should be like this: 

   ```console
   foo@bar:~$ ./bin/trustm_metadata -r 0xf1d6 
   ========================================================
   App DataStrucObj type 3     [0xF1D6] 
   [Size 0035] : 
   	20 21 C0 01 01 C1 02 00 00 C4 01 8C C5 01 40 D0 
   	03 E1 FC 07 D1 01 00 D8 07 21 E0 E8 FD 20 F1 D4 
   	F0 01 11 
   	LcsO:0x01, Version:0000, Max Size:140, Used Size:64, Change:LcsO<0x07, Read:ALW, MUD:Int-0xE0E8&&Conf-0xF1D4, Reset Type:SETCRE/FLUSH,
   ========================================================
   ```

2. Set the Lcso state for testing

    In the current Linux test script **`step1_protected_update_metadata_provisioning.sh`**, after writing the target metadata, the script changes the **LcsO** of the target OID from **creation** to **initialization** (for testing) by running:

    ```console
    ./bin/trustm_metadata -w 0xf1d6 -I
    ```

    You can verify the current state by reading metadata:
    ```console
    ./bin/trustm_metadata -r 0xf1d6
    ```

### **Step 2: Generate manifest and fragment for metadata protected update**

Run script: "**step2_generate_manifest.sh**"

 What it does:
 1. Reads metadata from target OID `0xF1D6`
 2. Extracts the current payload version from the metadata output
 3. Increments payload version  
    Note: Protected Update requires a monotonically increasing payload version.  
    If the payload version reaches the maximum limit (`0x7FFF`), the script prints a warning message. To reset it, run "**step0_reset_payload_version.sh**".
 4. Generates `metadata_manifest.dat` and `metadata_fragment.dat` for metadata protected update.

### **Step 3: Perform Protected Update for metadata**

Run script: **`step3_protected_update_metadata.sh`**

This script performs the metadata protected update using:
```console
./trustm_protected_update -k  0x$TARGET_OID -f metadata_fragment.dat -m metadata_manifest.dat
```

If the protected update is successful:
- The target OID metadata will be updated
- The payload version field in the target OID metadata will be updated to the new version used in Step 2
- Depending on the configured reset type (`F0 01 11`), the target data content may be flushed

The script reads out the metadata after the update:
```console
./bin/trustm_metadata -r 0x$TARGET_OID -X
```

Note: For detailed use case, please refer to the sample test scripts inside  "**linux-optiga-trust-m/scripts/protected_update_metadata/**"

## Optional helpers
### Reset payload version
Run script: **`step0_reset_payload_version.sh`**

Resets the payload version field in the target OID metadata.

### Reset target OID metadata
Run script: **`step0_reset_targetOID_metadata.sh`**  
Resets the change access condition and payload version for target OID.

### Clean all the temporary files in the folder
Run Script: "**cleanfiles.sh**" to clean all the temporary files in the folder.  

## How to run

Run the test scripts inside folder following the sequence: **`linux-optiga-trust-m/scripts/protected_update_metadata/`**:

```
# Step 1: Provisioning (usually one-time per device)
./step1_protected_update_metadata_provisioning.sh

# Step 2: Generate manifest + fragment
./step2_generate_manifest.sh

# Step 3: Perform protected update
./step3_protected_update_metadata.sh
```