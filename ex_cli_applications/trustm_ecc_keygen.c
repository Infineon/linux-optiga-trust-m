/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#define MAX_OID_PUB_CERT_SIZE   1728

typedef struct _OPTFLAG {
        uint16_t        read            : 1;
        uint16_t        type            : 1;
        uint16_t        output          : 1;
        uint16_t        keysize         : 1;
        uint16_t        savepubkey      : 1;
        uint16_t        bypass          : 1;
        uint16_t        dummy6          : 1;
        uint16_t        dummy7          : 1;
        uint16_t        dummy8          : 1;
        uint16_t        dummy9          : 1;
        uint16_t        dummy10         : 1;
        uint16_t        dummy11         : 1;
        uint16_t        dummy12         : 1;
        uint16_t        dummy13         : 1;
        uint16_t        dummy14         : 1;
        uint16_t        dummy15         : 1;
}OPTFLAG;

union _uOptFlag {
        OPTFLAG flags;
        uint16_t        all;
} uOptFlag;


void helpmenu(void)
{
    printf("\nHelp menu: trustm_ecc_keygen <option> ...<option>\n");
    printf("option:- \n");
    printf("-g <Key OID>    : Generate ECC Key in OID 0xNNNN \n");
    printf("-t <key type>   : Key type Auth:0x01 Enc :0x02 HFWU:0x04\n");
    printf("                           DevM:0X08 Sign:0x10 Agmt:0x20\n");
    printf("                           [default Auth]\n");
    printf("-k <key size>   : Key size ECC256:0x03 ECC384:0x04 ECC521:0x05\n");
    printf("                           BRAINPOOL256:0x13 BRAINPOOL384:0x15 BRAINPOOL512:0x16\n");
    printf("                           [default ECC256]\n");
    printf("-o <filename>   : Output Pubkey to file in PEM format\n");
    printf("-s              : Save Pubkey in <Key OID + 0x10E0>\n");
    printf("                  For ECC521/BRAINPOOL512: \n");
    printf("                  Save Pubkey in <Key OID + 0x10EF>\n");
    printf("-X              : Bypass Shielded Communication \n");
    printf("-h              : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;
    uint8_t eccheader256[] = {0x30,0x59, // SEQUENCE
                                0x30,0x13, // SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x08, // OID:1.2.840.10045.3.1.7
                                0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};

    uint8_t eccheader384[] = {0x30,0x76, // SEQUENCE
                                0x30,0x10, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x05, // OID:1.3.132.0.34
                                0x2B,0x81,0x04,0x00,0x22};
    uint8_t eccheader521[] = {0x30,0x81,0x9B, // SEQUENCE
                                0x30,0x10, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x05, // OID:1.3.132.0.35
                                0x2B,0x81,0x04,0x00,0x23}; 
    uint8_t eccheaderBrainPool256[] = {0x30,0x5A, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.7
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07};
    uint8_t eccheaderBrainPool384[] = {0x30,0x7A, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.11
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B};  
    uint8_t eccheaderBrainPool512[] = {0x30,0x81,0x9B, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.13
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d};                               
                                                                                
    uint8_t pubKey[200];
    uint16_t i;

    uint16_t pubKeyLen = sizeof(pubKey)+1000;
    uint8_t keyType=0x01;// default Auth
    uint8_t keySize=0x03;// default 256
    char *outFile = NULL;

    int option = 0;                    // Command line option.

    uOptFlag.all = 0;

    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
        // ---------- Check for command line parameters ----------
        if (argc < 2)
        {
            helpmenu();
            exit(0);
        }

        // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

        // Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "g:t:k:o:sXh")))
        {
            switch (option)
            {
                case 'g': // Generate Key ECC key E0F1-E0F3
                        uOptFlag.flags.read = 1;
                        optiga_key_id = trustmHexorDec(optarg);
                        if((optiga_key_id < 0xE0F1) || (optiga_key_id > 0xE0F3))
                        {
                                printf("Invalid ECC key OID!!!\n");
                                exit(0);
                        }
                        break;
                case 't': // Key Type
                        uOptFlag.flags.type = 1;
                        keyType = trustmHexorDec(optarg);
                        if ((keyType == 0x00) || (keyType & 0xc0))
                        {
                                printf("Key Type Error!!!\n");
                                exit(0);
                        }
                        break;
                case 'k': // Key Size
                        uOptFlag.flags.type = 1;
                        keySize = trustmHexorDec(optarg);
                        if ((keySize != 0x03) && (keySize != 0x04)&& (keySize != 0x05)&& (keySize != 0x13)&& (keySize != 0x15)&& (keySize != 0x16))
                        {
                                printf("Key Size Error!!!\n");
                                exit(0);
                        }
                        break;
                case 'o': // Output
                        uOptFlag.flags.output = 1;
                        outFile = optarg;
                        break;
                case 's': // Save pubkey
                        uOptFlag.flags.savepubkey = 1;
                        break;
                case 'X': // Bypass Shielded Communication
                    uOptFlag.flags.bypass = 1;
                    printf("Bypass Shielded Communication. \n");
                    break;
                case 'h': // Print Help Menu
                default:  // Any other command Print Help Menu
                        helpmenu();
                        exit(0);
                        break;
            }
        }
    } while (FALSE); // End of DO WHILE FALSE loop.

    if(uOptFlag.flags.bypass != 1)
    #ifdef HIBERNATE_ENABLE
        trustm_hibernate_flag = 1; // Enable hibernate Context Save
    #else
        trustm_hibernate_flag = 0; // disable hibernate Context Save
    #endif 
    else
        trustm_hibernate_flag = 0; // disable hibernate Context Save

    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS) {exit(1);}

    printf("========================================================\n");

    do
    {
        if(uOptFlag.flags.read == 1)
        {
            if(uOptFlag.flags.output != 1)
            {
                printf("Output filename missing!!!\n");
                break;
            }

            if(keySize == 0x04)
            {
                for (i=0; i < sizeof(eccheader384);i++)
                {
                    pubKey[i] = eccheader384[i];
                }
            }
            
            else if(keySize == 0x05)
            {
                for (i=0; i < sizeof(eccheader521);i++)
                {
                    pubKey[i] = eccheader521[i];
                }
            }
            else if(keySize == 0x13)
            {
                for (i=0; i < sizeof(eccheaderBrainPool256);i++)
                {
                    pubKey[i] = eccheaderBrainPool256[i];
                }
            } 
            else if(keySize == 0x15)
            {
                for (i=0; i < sizeof(eccheaderBrainPool384);i++)
                {
                    pubKey[i] = eccheaderBrainPool384[i];
                }
            } 
            else if(keySize == 0x16)
            {
                for (i=0; i < sizeof(eccheaderBrainPool512);i++)
                {
                    pubKey[i] = eccheaderBrainPool512[i];
                }
            } 
            else
            {
                for (i=0; i < sizeof(eccheader256);i++)
                {
                    pubKey[i] = eccheader256[i];
                }
            }

            printf("Generating Key to 0x%.4X\n",optiga_key_id);
            printf("Output File Name : %s \n", outFile);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
            
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_ecc_generate_keypair(me_crypt,
                                                              keySize,
                                                              keyType,
                                                              FALSE,
                                                              &optiga_key_id,
                                                              (pubKey+i),
                                                              &pubKeyLen);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                printf("Pubkey :\n");
                trustmHexDump(pubKey, (uint32_t) pubKeyLen+i);

                return_status = trustmWritePEM(pubKey, pubKeyLen+i,
                                                                                    outFile,"PUBLIC KEY");
                if (return_status != OPTIGA_LIB_SUCCESS)
                {
                    printf("Error when saving file!!!\n");
                }
            }
        }

        if(uOptFlag.flags.savepubkey == 1)
        {
            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            if((keySize == 0x05) || (keySize == 0x16))
            {
                return_status = optiga_util_write_data(me_util,
                                                   (optiga_key_id+0x10EF),
                                                   OPTIGA_UTIL_ERASE_AND_WRITE,
                                                   0,
                                                   (pubKey),
                                                   pubKeyLen+i);}
            else{
                return_status = optiga_util_write_data(me_util,
                                                   (optiga_key_id+0x10E0),
                                                   OPTIGA_UTIL_ERASE_AND_WRITE,
                                                   0,
                                                   (pubKey),
                                                   pubKeyLen+i);}                                      
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else{
            if((keySize == 0x05) || (keySize == 0x16)){
                printf("Write Success to OID: 0x%.4X.\n",(optiga_key_id+0x10EF));}
            else{
            printf("Write Success to OID: 0x%.4X.\n",(optiga_key_id+0x10E0));}
                 }
        }
    }while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");
    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return 0;
}
