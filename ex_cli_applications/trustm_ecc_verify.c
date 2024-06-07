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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

typedef struct _OPTFLAG {
    uint16_t    verify      : 1;
    uint16_t    input       : 1;
    uint16_t    signature   : 1;
    uint16_t    hash        : 1;
    uint16_t    pubkey      : 1;
    uint16_t    bypass      : 1;
    uint16_t    dummy6      : 1;
    uint16_t    dummy7      : 1;
    uint16_t    dummy8      : 1;
    uint16_t    dummy9      : 1;
    uint16_t    dummy10     : 1;
    uint16_t    dummy11     : 1;
    uint16_t    dummy12     : 1;
    uint16_t    dummy13     : 1;
    uint16_t    dummy14     : 1;
    uint16_t    dummy15     : 1;
}OPTFLAG;

union _uOptFlag {
    OPTFLAG flags;
    uint16_t    all;
} uOptFlag;

void _helpmenu(void)
{
    printf("\nHelp menu: trustm_ecc_verify <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID Key>   : Use Certificate from OID [0xE0E1-E0E3]\n");
    printf("-p <pubkey>    : Use Pubkey file\n");
    printf("-i <filename>  : Input Data file\n");
    printf("-s <signature> : Signature file\n");
    printf("-H <HashAlgo>  : SHA256:sha256 SHA384:sha384 SHA512:sha512\n");
    printf("-X             : Bypass Shielded Communication \n");
    printf("-h             : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    public_key_from_host_t public_key_details;
    char hash_algo[20] ="sha256";
    uint16_t optiga_oid;

    uint8_t signature [150];     //To store the signture generated
    uint16_t signatureLen = sizeof(signature);
    uint8_t digest[64];
    unsigned int digestLen=0;
    uint8_t pubkey[2048];
    uint32_t pubkeyLen;
    uint16_t pubkeySize;
    uint16_t pubkeyType;

    char *inFile = NULL;
    char *signatureFile = NULL;
    char *pubkeyFile = NULL;
    char name[100];
    FILE *fp = NULL;
    uint16_t i;
    uint16_t nid = 0;

    int option = 0;                    // Command line option.


/***************************************************************
 * Getting Input from CLI
 **************************************************************/
    uOptFlag.all = 0;
    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
        // ---------- Check for command line parameters ----------

        if (argc < 2)
        {
            _helpmenu();
            exit(0);
        }

        // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

        // Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "k:i:s:p:H::Xh")))
        {
            switch (option)
            {
                case 'k': // Cert OID
                    uOptFlag.flags.verify = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'i': // Input
                    uOptFlag.flags.input = 1;
                    inFile = optarg;
                    break;
                case 's': // Signature
                    uOptFlag.flags.signature = 1;
                    signatureFile = optarg;
                    break;
                case 'p': // Host Pubkey
                    uOptFlag.flags.pubkey = 1;
                    pubkeyFile = optarg;
                    break;
                case 'H': // Input
                    uOptFlag.flags.hash = 1;
                    if (optarg != NULL && optarg[0] != '-') {
                        strcpy(hash_algo, optarg);
                    } else if (optind < argc && argv[optind] != NULL && argv[optind][0] != '-') {
                        strcpy(hash_algo, argv[optind]);
                        optind++; // Move to the next argument
                    } else {
                        strcpy(hash_algo, "sha256");
                    }
                    printf("Hash Algorithm: %s\n", hash_algo);
                    break;
                case 'X': // Bypass Shielded Communication
                    uOptFlag.flags.bypass = 1;
                    printf("Bypass Shielded Communication. \n");
                    break;
                case 'h': // Print Help Menu
                default:  // Any other command Print Help Menu
                    _helpmenu();
                    exit(0);
                    break;
            }
        }
    } while (0); // End of DO WHILE FALSE loop.


/***************************************************************
 * Example
 **************************************************************/
    if(uOptFlag.flags.bypass != 1)
    #ifdef HIBERNATE_ENABLE
        trustm_hibernate_flag = 1; // Enable hibernate Context Save
    #else
        trustm_hibernate_flag = 0; // disable hibernate Context Save
    #endif 
    else
        trustm_hibernate_flag = 0; // disable hibernate Context Save

    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(1);

    printf("========================================================\n");

    do
    {
        if(uOptFlag.flags.input != 1)
        {
            printf("Input filename missing!!!\n");
            break;
        }

        if(uOptFlag.flags.signature != 1)
        {
            printf("Signature filename missing!!!\n");
            break;
        }

        signatureLen = trustmreadFrom(signature, (uint8_t *) signatureFile);
        if (signatureLen == 0)
        {
            printf("Error signature reading file!!!\n");
            break;
        }
        else // check for SEQUENCE/LENGTH
        {
            if ((signature[0] == 0x30)&&(signature[1] < 0x7F))  // SEQUENCE detected and Length < 0x7F
            {
                signatureLen = signature[1];
                for (i = 0;i < signatureLen; i++)
                {
                    signature[i] = signature[i+2];
                }
            }
            else{
                signatureLen = signature[2];
                for (i = 0;i < signatureLen; i++)
                {
                    signature[i] = signature[i+3];
                }
                }
        }

        if(uOptFlag.flags.hash == 1)
        {
            //open
            fp = fopen((const char *)inFile,"rb");
            if (!fp)
            {
                printf("error opening file : %s\n",inFile);
                exit(1);
            }         
            compute_hash(hash_algo, fp, digest, &digestLen);
            fclose(fp);
            trustmHexDump(digest,digestLen);	
         } else
         {
            digestLen = trustmreadFrom(digest, (uint8_t *) inFile);
            if (digestLen == 0)
            {
                printf("Error reading input file!!!\n");
                break;
            }
         }
        if(uOptFlag.flags.verify == 1)
        {
            printf("OID Cert            : 0x%.4X\n",optiga_oid);
            printf("Input File Name     : %s \n", inFile);
            printf("Signature File Name : %s \n", signatureFile);

            if(uOptFlag.flags.hash == 1)
                printf("Hash Digest : \n");
            else
                printf("Input data : \n");
            trustmHexDump(digest,digestLen);

            printf("Signature : \n");
            trustmHexDump(signature,signatureLen);

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_ecdsa_verify (me_crypt,
                                                       digest,
                                                       digestLen,
                                                       signature,
                                                       signatureLen,
                                                       OPTIGA_CRYPT_OID_DATA,
                                                       &optiga_oid);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
                printf("Verify Success.\n");

            printf("\n");
        }

        if(uOptFlag.flags.pubkey == 1)
        {
            printf("Pubkey file         : %s\n",pubkeyFile);
            printf("Input File Name     : %s \n", inFile);
            printf("Signature File Name : %s \n", signatureFile);

            trustmReadPEM(pubkey, &pubkeyLen, pubkeyFile, name, &pubkeySize, &pubkeyType,&nid);
            if (pubkeyLen == 0)
            {
                printf("Invalid Pubkey file \n");
                break;
            }
            if (strcmp(name, "PUBLIC KEY"))
            {
                printf("Invalid Public Key File!!!\n");
                break;
            }
            if (pubkeyType != EVP_PKEY_EC)
            {
                printf("Wrong Key Type!!!\n");
                break;
            }

            if(uOptFlag.flags.hash == 1)
                printf("Hash Digest : \n");
            else
                printf("Input data : \n");
            trustmHexDump(digest,digestLen);

            printf("Signature : \n");
            trustmHexDump(signature,signatureLen);

            printf("Pub key : [%d]\n",pubkeySize);
            trustmHexDump((pubkey),pubkeyLen);
                      
            if(pubkeySize == 256){
            if(nid == NID_brainpoolP256r1){
                pubkeySize = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;}
            else{
                pubkeySize = OPTIGA_ECC_CURVE_NIST_P_256;}
            }
            else if(pubkeySize == 384){
            if(nid == NID_brainpoolP384r1){
                pubkeySize = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;}
            else{
                pubkeySize = OPTIGA_ECC_CURVE_NIST_P_384;}
            }
            else if(pubkeySize == 512){
                pubkeySize = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;}
            else{
                pubkeySize = OPTIGA_ECC_CURVE_NIST_P_521;}

            public_key_details.public_key = pubkey;
            public_key_details.length = pubkeyLen;
            public_key_details.key_type = pubkeySize;

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_ecdsa_verify (me_crypt,
                                                       digest,
                                                       digestLen,
                                                       signature,
                                                       signatureLen,
                                                       OPTIGA_CRYPT_HOST_DATA,
                                                       &public_key_details);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                // stop performance timer.
                gettimeofday(&end, NULL);
                // Calculating total time taken by the program.
                time_taken = (end.tv_sec - start.tv_sec) * 1e6;
                time_taken = (time_taken + (end.tv_usec - start.tv_usec)) * 1e-6;
                printf("OPTIGA execution time: %0.4f sec.\n", time_taken);
                printf("Verify Success.\n");
            }
        }
    }while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return return_status;
}
