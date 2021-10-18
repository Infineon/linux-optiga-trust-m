# Integrity and Confidentiality Protected Update for data object

The following example shows how to do Integrity Protected Update for data object. 

1. Write Trust Anchor into the data object(can choose from 0xE0E1-0xE0E3, 0xE0E8-0XE0E9) and change the data object type to TA.

   In the test script "**protected_update_provisioning_step1.sh**" inside  "**linux-optiga-trust-m/scripts/protected_update_metadata/**", the data object 0xE0E8 is used to store the trust anchor. The metadata of the trust anchor OID can be set as shown in the test script: 

   ```console
   # Trust Anchor metadata setting
   TRUST_ANCHOR_META="2003E80111"
   ```

   E8 means data object Type, the following "01" means the length of the coming data, and the last"11" means Trust Anchor type.

   After running  "**protected_update_provisioning_step1.sh**", the data object type is set to Trust Anchor. 

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

   For detailed data object type, please refer to Table70(Page100) in https://github.com/Infineon/optiga-trust-m/blob/trust_m1_m3/documents/OPTIGA_Trust_M_Solution_Reference_Manual_v3.15.pdf

   For detailed metadata associated with data and key objects, please refer to Table74(Page106) in https://github.com/Infineon/optiga-trust-m/blob/trust_m1_m3/documents/OPTIGA_Trust_M_Solution_Reference_Manual_v3.15.pdf

2. Write Protected Update Secret into the data object(can choose from 0xF1D0, 0xF1D4-0XF1DB) and change the data object type to UPDATSEC.

   In the test script "**protected_update_provisioning_step1.sh**" inside  "**linux-optiga-trust-m/scripts/protected_update_metadata/**", the data object 0xF1D4 is used to store the protected update secret. The metadata of the protected update secret OID can be set as shown in the test script: 

   ```console
   # Protected Update OID metadata setting
   PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"
   ```

   E8 means data object Type, the following "01" means the length of the coming data, and the last"23" means Protected Update Secret type.

   After running  "**protected_update_provisioning_step1.sh**", the data object type is set to Protected Update Secret. 

   ```console
   foo@bar:~$ ./bin/trustm_metadata -r 0xf1d4
   App DataStrucObj type 3     [0xF1D4] 
   [Size 0027] : 
   	20 19 C0 01 01 C4 01 8C C5 01 40 D0 03 E1 FC 07 
   	D1 03 E1 FC 07 D3 01 00 E8 01 23 
   	LcsO:0x01, Max Size:140, Used Size:64, Change:LcsO<0x07, Read:LcsO<0x07, Execute:ALW, Data Type:UPDATSEC, 
   ```

   For detailed data object type, please refer to Table70(Page100) in https://github.com/Infineon/optiga-trust-m/blob/trust_m1_m3/documents/OPTIGA_Trust_M_Solution_Reference_Manual_v3.15.pdf

   For detailed metadata associated with data and key objects, please refer to Table74(Page106) in https://github.com/Infineon/optiga-trust-m/blob/trust_m1_m3/documents/OPTIGA_Trust_M_Solution_Reference_Manual_v3.15.pdf

3. Write test data into the target data object and change the metadata of the target OID accordingly. The version number,metadata update descriptor and Reset type are the parts which are needed to be changed. The metadata of the Target OID can be set as shown in the test script: 

   ```console
   # Target OID metadata setting for protected update 
   TARGET_OID_META="2010C1020000F00101D80721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"
   ```

   C1 means the version number, the following "02" means the length of the coming data, and the following"0000" the means version number is "0000".

   F0 means Reset type, the following "01" means the length of the coming data, and the following"11" means bring back to creation state and flush the data inside.

   D8 means metadata Update descriptor, this  tag  defines  the  condition  under  which  the  metadata update is permitted. The following "03" means the length of the coming data."21" means integrity protection," $TRUST_ANCHOR_OID" is the OID used to store Trust Anchor,"20" means confidentiality protection,"${PROTECTED_UPDATE_SECRET_OID}"is the OID used to store Protected Update Secret.

   For detailed metadata associated with data and key objects, please refer to Table74(Page106) in https://github.com/Infineon/optiga-trust-m/blob/trust_m1_m3/documents/OPTIGA_Trust_M_Solution_Reference_Manual_v3.15.pdf

   After running  "**protected_update_provisioning_step1.sh**", the metadata of target OID should be like this: 

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

4. Set the Lcso to Operational state by running the command below:

   ```console
   foo@bar:~$ ./bin/trustm_metadata -w 0xf1d6 -O
   ========================================================
   App DataStrucObj type 3     [0xF1D6] 
   
   	20 03 C0 01 07 
   	LcsO:0x07, 
   Write Success.
   ========================================================
   ```

   The metadata of the target OID is shown as below:

   ```console
   foo@bar:~$ ./bin/trustm_metadata -r 0xf1d6 
   ========================================================
   App DataStrucObj type 3     [0xF1D6] 
   [Size 0035] : 
   	20 21 C0 01 07 C1 02 00 00 C4 01 8C C5 01 40 D0 
   	03 E1 FC 07 D1 01 00 D8 07 21 E0 E3 FD 20 F1 D4 
   	F0 01 11 
   	LcsO:0x07, Version:0000, Max Size:140, Used Size:64, Change:LcsO<0x07, Read:ALW, MUD:Int-0xE0E3&&Conf-0xF1D4, Reset Type:SETCRE/FLUSH,
   ========================================================
   ```

5. Run the windows program to get the correct manifest and fragment 

   1. Go to  "**\trustm_lib\examples\tools\protected_update_data_set\samples**" and open command prompt

   2. Run this example command:

      ```shell
      C: \optiga-trust-m\examples\tools\protected_update_data_set\samples>..\bin\protected_update_data_set.exe payload_version=3 ^
      trust_anchor_oid=E0E8 ^
      target_oid=F1D6 ^
      sign_algo=ES_256 ^
      priv_key=..\samples\integrity\sample_ec_256_priv.pem ^
      payload_type=metadata ^
      metadata=..\samples\payload\metadata\metadata.txt ^
      content_reset=0 ^
      secret=..\samples\confidentiality\secret.txt ^
      label="test" ^
      enc_algo="AES-CCM-16-64-128" ^
      secret_oid=F1D4
      ```

      Note:

      1. There are some options to configure in this command. For more details, please go to https://github.com/Infineon/optiga-trust-m/tree/master/examples/tools/protected_update_data_set

      2. The example metadata.txt used here as sample is: 200BC00101D10100D003E1FC07

      3. The private key for sample_ec_256_cert.pem and metadata.txt must be available in the corresponding folder

6. Transfer the manifest and fragment to Raspberry Pi and convert them to manifest.dat and fragment.dat file

7. Use the manifest and fragment as input for trustm_protected_update as stated in "**protected_update_step2.sh **"under "**linux-optiga-trust-m/scripts/protected_update_metadata/**"

   If the protected update is successful, Lcso of this data object will be changed back to creation state and the certificate inside the target data object will be flushed.

   ```console
   ========================================================
   App DataStrucObj type 3     [0xF1D6] 
   [Size 0035] : 
   	20 21 C0 01 01 C1 02 00 03 C4 01 8C C5 01 00 D0 
   	03 E1 FC 07 D1 01 00 D8 07 21 E0 E8 FD 20 F1 D4 
   	F0 01 11 
   	LcsO:0x01, Version:0003, Max Size:140, Used Size:0, Change:LcsO<0x07, Read:ALW, MUD:Int-0xE0E8&&Conf-0xF1D4, Reset Type:SETCRE/FLUSH, 
   ========================================================
   ```

Note: For detailed use case, please refer to the sample test scripts inside  "**linux-optiga-trust-m/scripts/protected_update_metadata/**"

