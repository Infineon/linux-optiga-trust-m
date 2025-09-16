[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## Updating Platform Binding Secret (PBS) for OPTIGA™ Trust M

Guide to update the Platform Binding Secret (PBS) for OPTIGA™ Trust M in a Linux Tool Environment
## Overview

The Platform Binding Secret (PBS) is used to establish Shielded Connection between the host MCU and the OPTIGA™ Trust M chip. 

- For OPTIGA™ Trust M V1 and V3 variants, the PBS is generally a fixed default value. 

- For OPTIGA™ Trust M Express/MTR variants, the PBS is unique per chip, provided by Infineon in a secure PBS bundle file and not publicly disclosed.

To ensure correct and secure operation, the PBS value should be transferred from the bundle file to the host MCU for a protected I2C connection. This guide describes how to correctly update the PBS value for host MCU to align with the PBS value stored inside OPTIGA™ Trust M .

## OPTIGA™ Trust M V1/V3 Use Case

When using OPTIGA™ Trust M V1or V3 with the default shared secret, no further action is required to configure the PBS value after running the installation script.

## OPTIGA™ Trust M MTR/Express Use Case

When using an OPTIGA™ Trust M MTR/Express device:

1. Navigate to `/linux-optiga-trust-m/pbs`.

2. Create one empty directory call `bundle_file` and copy exactly **one** zipped PBS bundle file in this directory.

3. Create one empty directory call `transport_key` and copy exactly **one** corresponding transport key file in this directory.

4. Run the `updating_pbs.py` script to extract and apply the PBS value from the bundle.

```shell
cd /linux-optiga-trust-m/pbs
python3 updating_pbs.py
```

Once completed, the `pbsfile.txt` will be updated with the extracted PBS value, and the  `pbsfile.txt` will be used to update the platform binding shared secret in pal_os_datastore.c to allow the secure communication established for host and OPTIGA™ Trust M .

Note: if switching from OPTIGA™ MTR/Express to OPTIGA™ V1/V3, you need:

1. Navigate to `/linux-optiga-trust-m/pbs`.
  
2. Ensure that all files inside both the `bundle_file` and `transport_key` directories are cleared.
  
3. Run the `updating_pbs.py` script to overwrite `pbsfile.txt` with the default PBS value.


```shell
cd /linux-optiga-trust-m/pbs
python3 updating_pbs.py
```

If the default PBS value stored inside `0xE140` for OPTIGA™ Trust V1/V3 has been modified, you need manually update the `pbsfile.txt` content with the corresponding new value to establish the secure communication between host MCU and OPTIGA™ Trust M

