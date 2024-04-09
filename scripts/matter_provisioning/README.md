# OPTIGA™ Trust M MTR: Matter Provisioning
This folder contains scripts to make the provisioning of Matter credentials simple and easy.
The contained scripts can be used "as-is" in combination with a Raspberry Pi 4B, or taken as base for a reference implementation. 

This guide is only relevant for the [OPTIGA™ Trust M MTR](https://www.infineon.com/optiga-trust-m-mtr) variant.

Documentation on the OPTIGA Trust M and Getting Started Guides can be found in the [OPTIGA Trust M Repository](https://www.github.com/infineon/optiga-trust-m).

Installing the OPTIGA Trust M Linux-tools (this reposistory, see [here](../../README.md#getting-started) for instructions) is required.

- [OPTIGA™ Trust M MTR: Matter Provisioning](#optiga-trust-m-mtr-matter-provisioning)
  - [OPTIGA™ Trust M MTR Object Map](#optiga-trust-m-mtr-object-map)
  - [Hardware Prerequisites](#hardware-prerequisites)
- [Step-by-step Late-stage Provisioning](#step-by-step-late-stage-provisioning)
  - [Step 1: Script Configuration](#step-1-script-configuration)
  - [Step 2: Credential Selection](#step-2-credential-selection)
  - [Step 3: Post-Processing](#step-3-post-processing)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [Scripts Documentation \& Usage](#scripts-documentation--usage)
  - [matter\_provsioning\_master.sh](#matter_provsioning_mastersh)
  - [matter\_bundle\_provisioning.sh](#matter_bundle_provisioningsh)
  - [matter\_test\_provisioning.sh](#matter_test_provisioningsh)
  - [verify\_configuration.sh](#verify_configurationsh)
  - [configure\_security\_monitor.sh](#configure_security_monitorsh)


## OPTIGA™ Trust M MTR Object Map

![OPTIGA™ Trust M MTR Objects after Provisioning](../../pictures/mr_object_map.png)

The above image shows the state of the OPTIGA™ Trust M MTR *after* this provisioning mechanism.

Noted in ocean green color are the objects provisioned by Infineon, like the ECC and RSA Keys and Certificates. This is also information, which can be retrieved from the Cloud Service Provider, who also hosts the CSA certified Matter PKI.

This Cloud Service Provider is used by Matter OEMs to generate device individual Matter Device Attestation Certificates (DACs) and download them in the form of a Bundle File per Reel (4k pcs) or per evaluation sample (1 pcs).

The information inside the bundle file, containing (at least) Matter DAC and PAI is then provisioned to the OPTIGA™ Trust M MTR via the following scripts, adding the orange colored objects to the Secure Element. Additonally, the Certificate Declaration (CD) can be written to the OPTIGA™ Trust M MTR through the scripts.

As an OEM, you will receive your OPTIGA™ Trust M MTR in the following configuration. All objects are pre-provisioned by Infineon inside a secure and certified production environment.

### Table 1: OPTIGA Trust M MTR Object & Metadata Configuration by Infineon

| Object ID | Description                 | Relationship            | LcsO           | Read | Change                             | Execute | Intermediate CA                                                                         |
| --------: | --------------------------- | ----------------------- | -------------- | ---- | ---------------------------------- | ------- | --------------------------------------------------------------------------------------- |
|    0xE0F0 | ECC NIST P256 Private Key 1 | Bound to Cert in 0xE0E0 | Operational    | NEV  | PBS & Auto*                        | ALW     |                                                                                         |
|    0xE0F1 | ECC NIST P256 Private Key 2 | Bound to Cert in 0xE0E1 | Operational    | NEV  | PBS & Auto*                        | ALW     |                                                                                         |
|    0xE0FC | RSA 2048 Private Key 1      | Bound to Cert in 0xE0FC | Operational    | NEV  | PBS & Auto*                        | ALW     |                                                                                         |
|    0xE0E0 | ECC Certificate 1           | Bound to Key in 0xE0F0  | Initialization | ALW  | (ALW if LcsO < OP) or (PBS & Auto) | ALW     | [IFX Int. CA 306](https://pki.infineon.com/OptigaTrustEccCA306/OptigaTrustEccCA306.crt) |
|    0xE0E1 | ECC Certificate 2           | Bound to Key in 0xE0F1  | Operational    | ALW  | PBS & Auto                         | ALW     | [IFX Int. CA 306](https://pki.infineon.com/OptigaTrustEccCA306/OptigaTrustEccCA306.crt) |
|    0xE0E2 | RSA Certificate 1           | Bound to Key in 0xE0FC  | Operational    | ALW  | PBS & Auto                         | ALW     | [IFX Int. CA 309](https://pki.infineon.com/OptigaTrustRsaCA309/OptigaTrustRsaCA309.crt) |
|    0xE140 | Plattform Binding Secret    |                         | Operational    | NEV  | PBS & Auto                         | ALW     |                                                                                         |
|    0xF1D0 | Authorization Reference     |                         | Operational    | NEV  | PBS & Auto                         | PBS     |                                                                                         |


The scripts in this folder will change some of the objects on the OPTIGA™ Trust M MTR, such that it contains the following objects **after** the late-stage provisioning. This is also the recommended configuration during the device lifecycle.

### Table 2: OPTIGA Trust M MTR Object & Metadata Configuration after late-stage Provisioning

|   Object ID | Description                  | Relationship            | Recommended LcsO | Read | Change                             | Execute | Provisioned By |
| ----------: | ---------------------------- | ----------------------- | ---------------- | ---- | ---------------------------------- | ------- | -------------- |
|      0xE0F0 | ECC NIST P256 Private Key 1  | Bound to Cert in 0xE0E0 | Operational      | NEV  | PBS & Auto*                        | ALW     | IFX            |
|      0xE0F1 | ECC NIST P256 Private Key 2  | Bound to Cert in 0xE0E1 | Operational      | NEV  | PBS & Auto*                        | ALW     | IFX            |
|      0xE0FC | RSA 2048 Private Key 1       | Bound to Cert in 0xE0FC | Operational      | NEV  | PBS & Auto*                        | ALW     | IFX            |
|      0xE0E0 | Matter DAC                   | Bound to Key in 0xE0F0  | Operational      | ALW  | (ALW if LcsO < OP) or (PBS & Auto) | ALW     | OEM            |
|      0xE0E1 | ECC Certificate 2            | Bound to Key in 0xE0F1  | Operational      | ALW  | PBS & Auto                         | ALW     | IFX            |
|      0xE0E2 | RSA Certificate 1            | Bound to Key in 0xE0FC  | Operational      | ALW  | PBS & Auto                         | ALW     | IFX            |
|      0xE0E8 | Matter PAI                   |                         | Operational      | ALW  | PBS & Auto                         | ALW     | OEM            |
|      0xE140 | Plattform Binding Secret     |                         | Operational      | NEV  | PBS & Auto                         | ALW     | IFX            |
|      0xF1D0 | Authorization Reference      |                         | Operational      | NEV  | PBS & Auto                         | PBS     | IFX            |
|      0xF1E0 | Matter CD                    |                         | Operational      | ALW  | PBS & Auto                         | ALW     | OEM            |
| 0xE0F2/F3** | Matter Node Operational Keys |                         | Operational      | ALW  | ALW*                               | ALW     | Application    |
| 0xF1D8/D9** | Matter HKDF & HMAC           |                         | Operational      | ALW  | ALW                                | ALW     | Application    |

\* Keys can never be written to directly, they can only be generated through the OPTIGA™ Trust M functions.

** These slots _may_ be used during operation of the device. Subject to implementation on the host. They are not provisioned by these scripts.

## Hardware Prerequisites
A direct I2C connection to the OPTIGA™ Trust M is required for this provisioning mechanism to work. 
A connection to the RST Pin of the Trust M is not required, as this can be done as a Software Reset through the Linux Host library.

![OPTIGA™ Trust M Schematic Reference](../../pictures/reference_schematic.png)

For production usecases, it is also recommended to apply the RST of any other controllers or devices on the same I2C bus to guarantee uninterrupted communication of RPi and Trust M during the short provisioning phase.

For evaluation purposes, it is recommended to use the [OPTIGA™ Trust M MTR Shield](https://www.infineon.com/optiga-trust-m-mtr-shield) in combination with the [MikroE Pi4 Click-Shield](https://www.mikroe.com/pi-4-click-shield). Here, all connections are already routed in a plug-and-play solution.

<!---
# Certificate Claiming
--->

# Step-by-step Late-stage Provisioning

> Everything which is written in [brackets] must be replaced with the individual filename. E.g. [PAI_FILENAME].pem would become matter_infineon_pai.pem.

To provision your OPTIGA Trust M MTR chips, three steps are required, most of which are fully automated by the `matter_provisioning_master.sh` script:

1) Configure the script and Trust M object location.
2) Select if you want to write Matter _Test_ Credentials or Matter _Productive_ Credentials
3) Do some post-processing and verification.

**tl;dr:** To write your Matter Credentials to the OPTIGA Trust M MTR, use the following command inside this folder:
```bash
./matter_provisioning_master.sh -b [path_to_bundle_file_3.0.7z] -k [transport_key] -c [path_to_certificate_declaration.bin] -v -o
```


## Step 1: Script Configuration

It is possible to reconfigure the Object-ID, in which the certificates will be stored. Note that you will have to edit this in the Matter SDK accordingly. Edit the following lines in the file `config.sh`:

```bash
MATTER_DAC_LOC=0xE0E0   # Object ID of DAC
MATTER_PAI_LOC=0xE0E8   # Object ID of PAI
MATTER_CD_LOC=0xF1E0    # Object ID of CD 

# Additionally, if console log output is needed, change "/dev/null" to "/dev/stdout".
DEBUG_OUTPUT="/dev/null" 
```

Several scripts have been prepared to make the Matter credential provisioning as easy as possible. The main interface will be the ```matter_provisioning_master.sh``` script. To make sure, that all scripts can be executed, move into this folder on the command line and type:

```bash
cd linux-optiga-trust-m/scripts/matter_provisioning
chmod +x *.sh
```

## Step 2: Credential Selection

You can choose to initially evaluate the OPTIGA Trust M MTR with Matter Development Credentials or use the (productive) Credentials provided and rooted by Kudelski Keystream. For the latter option, you need to claim and download the respective bundle file from Keystream. This applies to the Device Attestation Certificate (DAC) and Product Attestation Intermediate (PAI).

Additionally, you will need a Certificate Declaration for your device. This CD can be optionally stored on the OPTIGA Trust M MTR.

The [OPTIGA™ Trust M MTR Shield](https://www.infineon.com/optiga-trust-m-mtr-shield) comes already pre-configured with Matter Development Credentials (DAC, PAI, CD). Hence, you can directly start evaluating with these credentials in combination with the Matter SDK. Afterwards, come back to this guide and provision your individual, Kudelski rooted credentials to the OPTIGA Trust M MTR.

### Option A: Matter Production Credentials

This usecase assumes the usage and provisioning of productive Matter credentials which are claimed from the provided Cloud-Services for the individual OPTIGA™ Trust M MTR chips in the form of a so-called "Bundle File".

<details>
<summary>What is a "Bundle File"</summary>

### The Infineon Bundle File

The bundle file is an "archive of archives", i.e. a 7-Zip archive containing multiple sub-archives with the DACs, PAI and the other, Infineon Rooted, TLS Certificates.

```shell
    Bundle file 
------- reelID_vx.y.7z -------
|                                |
|   reelID_E0E1_Certs.7z         |
|                                |
|   reelID_E0E2_Certs.7z         |
|                                |
|   reelID_keyOID=E0F0_DACs.7z   |   
|                                |
|   reelID_keyOID=E0F0_PAI.7z    |   
|                                |
|   reelID_keys.7z               |
|                                |
|   README.txt                   |
|                                |
--------------------------------
```
**reelID_E0E1_Certs.7z**

This archive contains the certificates stored in data object E0E1, as device 
individual .pem files. 
The individual file names follow the convention: chipID_E0E1.pem to allow 
matching certificate - device.
Please note that the certificate from E0E1 data object is usable only under 
shielded connection!

**reelID_E0E2_Certs.7z**

This archive contains the certificates stored in data object E0E2, as device 
individual .pem files. 
The individual file names follow the convention: chipID_E0E2.pem to allow 
matching certificate - device.

**reelID_keyOID=E0F0_DACs.7z**

This archive contains the Device Attestation Certificates (DAC) corresponding 
to the private key in slot E0F0, as device individual .pem files. 
The individual file names follow the convention: chipID_keyOID=E0F0_DAC.pem 
to allow matching certificate - device.

**reelID_keyOID=E0F0_PAI.7z**

This archive contains the Product Attestation Intermediate (PAI) Certificate, 
which was used to generate and sign the DACs. 
It contains exactly one file with name keyOID=E0F0_PAI.pem.

**reelID_keys.7z**

This file is an encrypted archive containing chip individual PBS and 
authorization keys. The decryption key is available at keySTREAM.
PBS and authorization keys are included as text files in this archive. 
The files have 1 record/line, structured as: 

chipID, PBS key 
or
chipID, authorization key 

The records are represented as hexadecimal strings, i.e. 2 charcters/byte. 

</details>

<br>

Download the bundle file from the Cloud Service's webpage and copy it to your Raspberry Pi. As a current working directory, we assume this directory.

Copy the bundle file with your favorite tool (CLI, GUI, etc.) to this directory (i.e. ```linux-optiga-trust-m/scripts/matter_provisioning```). As an example, we will use [APPNOTE_bundle-file_v3.0.7z] to identify the bundle file and [CD_path.bin] for the Certificate Declaration in the following commands.

The ```matter_provisioning_master.sh``` script will now be used to flash Matter DAC, PAI (and optionally CD) certificates to the individual OPTIGA™ Trust M MTR.

> [!IMPORTANT]
> Per default, the script does not set any metadata options to the OPTIGA™ Trust M objects, meaning they can be rewritten at any point in time. This is good for evaluation purposes, but not recommended for final products. Here, each object LcsO shall be set to "operational". See Section [Set Operational](#set-objects-state-to-operational) on how to enable this option in the script.

### Matter Credentials Provisioning

To provision the Matter credentials, the master script needs two inputs: The location of the bundle file and *optional* he location of the Certificate Declaration. 

Connect the OPTIGA™ Trust M MTR to the Raspberry Pi’s I2C as described in the [Hardware Section](#hardware-prerequisites) and execute the master script via:

    ./matter_provisioning_master.sh -b [APPNOTE_bundle-file_v3.0.7z] -c [CD_path.bin]

The master script will:
1.	Extract the bundle file to the tmp folder.
2.	Extract/copy the DACs and PAI to the tmp/matter_cred folder.
3.	Until the user cancels the session via pressing CTRL+C (sending an interrupt) or another error occurs, the script will remain in an infinite while loop where:
    1.	Probes for a new OPTIGA™ Trust M Chip via trying to read the Chip-UID
    2.	Searches for the correct DAC via the Chip-UID
    3.	Flashes corresponding DAC, PAI and CD in the respective OPTIGA™ Trust M MTR certificate and data slots.
4.	Once the flashing of a chip is complete, connect a new chip to flash the next one without exiting the script.

### Option B: Matter Test Credentials
This usecase assumes the usage and provisioning of Matter Test credentials, which are issued by the CSA for product development and testing.

The Matter DAC is generated and issued based on the individual pre-loaded ECC private key of the OPTIGA™ Trust M. This can be used to speed up development based on test-credentials or to reset your evaluation samples.

The OPTIGA™ Trust M MTR Shield comes pre-provisioned with these Test-Credentials out of the box to make evaluation quick and easy. For all other OPTIGA™ Trust M products, run

    ./matter_provisioning_master.sh -t

to generate and write Matter Test Credentials (DAC, PAI and CD) to the respective OPTIGA™ Trust M object slots. The Test DAC uses the public key extracted from the Infineon pre-provisioned certificate stored in slot 0xE0E0.

> [!NOTE]
> OPTIGA Trust M MTR Shields of HW Revision ≤ v2.1 cannot be provisioned with Matter Test Credentials by this script. The LcsO of the slot 0xE0E0 is already set to "operational" and the certificate can only be exchanged by using the PBS and Authorization Reference. Download the Bundle File from Kudelski Keystream for your Evaluation Shield and use [Option A](#option-a-matter-production-credentials) instead. You need to additionally supply the Transport Key for this bundle file through the ```-k [key]``` option. 

## Step 3: Post-Processing
### Verify configuration

It is possible to directly test, if the Matter DAC is correctly working and also matches the on-chip private key. A simple ECDSA Signature Generation/Verification suffices and is implemented in the script. 

Add the ```-v``` option to any of the input commands, e.g.:

    ./matter_provisioning_master.sh -b APPNOTE_bundle-file_v1.0.7z -c CD_path.bin -v


### Set Objects state to "Operational"

> [!WARNING] 
> ⚠️ **This is not reversible. Proceed with caution.** ⚠️

Any of the above options only put the credentials to the designated Trust M Credential Slots. Add the following option `-o` to additionally set the metadata configuration and operational LcsO as described in the configuration table.

    ./matter_provisioning_master.sh -b APPNOTE_bundle-file_v1.0.7z -c CD_path.bin -v -o

### Optional: Matter Credential Provisioning & Modify Security Monitor Configuration

The OPTIGA Trust M has a security functionality called ["Security Monitor"](https://github.com/Infineon/optiga-trust-m/wiki/Security-Monitor). If your application requires this feature to be disabled, you can do so for this specific configuration. **Infineon does not recommend to do this.**  

To provision the Matter credentials and configure the security monitor, the master script needs at least two inputs: The location of the bundle file and the transport key which is used to decrypt the chip-unique secrets. These secrets (PBS and AutoRef) are required as a second factor to update the Security Monitor Configuration. Again, optionally, the CD can be supplied.

As an optional third input, the wanted security monitor configuration can be supplied as defined in Section 4.6.3 of the [Solution Reference Manual](https://github.com/Infineon/optiga-trust-m/tree/develop/documents). The default configuration from the script is to disable the Security Monitor entirely.

This guide assumes, that the bundle file is in the matter_provisioning folder.

Connect the OPTIGA™ Trust M MTR to the Raspberry Pi’s I2C as described in Section 2.1 and execute the master script via:

    ./matter_provisioning_master.sh -b APPNOTE_bundle-file_v1.0.7z -c CD_path.bin -k [SAMPLE_TKEY] -s 0

If a custom security monitor configuration shall be used, input this configuration after the -s argument:

    ./matter_provisioning_master.sh -b APPNOTE_bundle-file_v1.0.7z -c CD_path.bin -k [SAMPLE_TKEY] -s 010050100000000

The master script will:
1.	Extract the bundle file to the tmp folder.
2.	Extract/copy the DACs and PAI to the tmp/matter_cred folder.
3.	Extract and Decrypt the Authorization Reference and Platform Binding Secrets to the tmp/keys folder.
4.	Until the user cancels the session via pressing CTRL+C (sending an interrupt) or another error occurs, the script will remain in an infinite while loop where:
    1.	Probes for a new OPTIGA™ Trust M Chip via trying to read the Chip-UID
    2.	Searches for the correct DAC via the Chip-UID
    3.	Flashes corresponding DAC, PAI and CD in the respective OPTIGA™ Trust M certificate and data slots.
    4.	Searches for the correct PBS & AutoRef Secret via the Chip-UID
    5.	Pairs the Host and OPTIGA™ Trust M and starts an authorized and encrypted session
    6.	Writes the updated Security Monitor Configuration to 0xE0C9
5.	Once the flashing of a chip is complete, connect a new chip to flash the next one without exiting the script.

# Troubleshooting and FAQ

### OPTIGA Trust M MTR Shields with Hardware Revision ≤ v2.1
These shields have a OPTIGA Trust M Object configuration which does not reflect the configuration as stated in [Table 1](#table-1-optiga-trust-m-mtr-object--metadata-configuration-by-infineon). Instead, the LcsO of Object 0xE0E0 is already set to "operational", which will require you to use the PBS and Authorization Reference Secrets for provisioning your DAC. 

To do this, add to any command of the `matter_provisioning_master.sh` script the `-k` option and supply your personalized Transport Key. You can find this key online in the Kudelski Keystream interface. Hence, use the following command instead:

    ./matter_provisioning_master.sh -b [path_to_bundle_file_3.0.7z] -c [path_to_certificate_declaration.bin] -k [SAMPLE_TKEY] -v

# Scripts Documentation & Usage

## matter_provsioning_master.sh

Master Script to sequentially provision OPTIGA™ Trust M MTR chips with test or productive Matter credentials.
If "0" is given as argument for the `-s` option, the Security Monitor will be configured with '000050100000000', effectively disabling the Security Monitor.

**Sample Usage:**

    ./matter_provisioning_master.sh -b [path_to_bundle_file_3.0.7z] -c [path_to_certificate_declaration.bin] -v -o

Options: 

| Option      | Description                                                                                  | Sample                         | Additional Info                                    |
| ----------- | -------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------- |
| -t          | Provision Matter Test Credentials                                                            |                                | Either -t or -b option                             |
| -b [file]   | Provision Matter Credentials from Bundle File                                                | -b APPNOTE_bundle-file_v3.0.7z | Either -t or -b option. Shall be 7z file.          |
| -k [key]    | Transport Key for Bundle File                                                                | -k 'ABC$123%DEF567'            | Needs to be in combination with -b and -s options. |
| -s [config] | Security Monitor Configuration, either 0 for the default configuration or some configuration | -s 010050100000000             | Needs to be in combination with -b and -k options. |
| -c [file]   | Path to Certificate Declaration File                                                         | -c Chip-Test-CD-Cert.bin       | Shall be binary (*.bin) file                       |
| -o          | Flag to set the Metadata (LcsO Operational)                                                  |                                |                                                    |
| -v          | Flag to verify configuration                                                                 |                                |                                                    |
| -h          | Print help                                                                 |                                |                                                    |

## matter_bundle_provisioning.sh
Script to provision a single OPTIGA™ Trust M MTR chip with DAC & PAI Information in the given folder structure.


```
tmp/matter_cred
├── chip_id1_keyOID=E0F0_DAC.pem
├── ...
├── chip_idX_keyOID=E0F0_DAC.pem
└── keyOID=E0F0_PAI.pem

tmp/keys
├── auto_keys.txt
└── PBS_keys.txt
```

**Sample Usage:**

    ./matter_bundle_provisioning.sh -p ./tmp/matter_cred -c 0A091B5C0015009A0087 -k ./tmp/keys

Options: 

| Option   | Description                                                                   | Sample                  | Additional Info               |
| -------- | ----------------------------------------------------------------------------- | ----------------------- | ----------------------------- |
| -p [dir] | Path to Matter Credential Directory. This should contain the DAC, PAI and CD. | -p ./tmp/matter_cred    | In combination with -c option |
| -c [CID] | Chip-ID of the current Trust M sample                                         | -c 0A091B5C0015009A0087 | In combination with -p option |
| -k [dir] | Path to Matter Keys Directory. This should contain the PBS and AuthRef Keys.  | -k ./tmp/keys           | In combination with -c option |

## matter_test_provisioning.sh
Script to provision a single OPTIGA™ Trust M MTR chip with Matter test credentials.

**Sample Usage:**

    ./matter_test_provisioning.sh

## verify_configuration.sh
Script to verify the configuration of a single OPTIGA™ Trust M MTR. Will generate a ECDSA Signature with key in OID 0xE0F0 and verify it with the Public Key of the DAC.

**Sample Usage:**

    ./verify_configuration.sh

## configure_security_monitor.sh
Script to configure the Security Monitor of a single OPTIGA™ Trust M chip with a given configuration.


```
input_dir
├── auto_keys.txt
└── PBS_keys.txt
```

Where the key files are each CSV files containing the chip-ID and respective key as from the Bundle file.#
If "0" is given as argument for the `-s` option, the Security Monitor will be configured with '000050100000000', effectively disabling the Security Monitor.

**Sample Usage:**

    ./configure_security_monitor.sh -p ./tmp/matter_cred -c 0A091B5C0015009A0087 -s 0

Options: 

| Option      | Description                                                                                  | Sample                  | Additional Info                                    |
| ----------- | -------------------------------------------------------------------------------------------- | ----------------------- | -------------------------------------------------- |
| -p [dir]    | Path to Keys Directory. This should contain the "PBS_keys.txt" and "auto_keys.txt" files.    | -p ./tmp/keys           | In combination with -c option                      |
| -c [CID]    | Chip-ID of the current Trust M sample                                                        | -c 0A091B5C0015009A0087 | In combination with -p option                      |
| -s [config] | Security Monitor Configuration, either 0 for the default configuration or some configuration | -s 010050100000000      | Needs to be in combination with -c and -p options. |
