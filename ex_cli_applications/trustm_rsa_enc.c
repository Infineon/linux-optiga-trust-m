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
#include <sys/time.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#define MAX_OID_PUB_CERT_SIZE   1728

typedef struct _OPTFLAG {
    uint16_t    enc         : 1;
    uint16_t    input       : 1;
    uint16_t    output      : 1;
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
    printf("\nHelp menu: trustm_rsa_enc <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID Key>  : Select key for encrypt OID 0xNNNN \n");
    printf("-p <pubkey>   : Use Pubkey file\n");
    printf("-o <filename> : Output to file \n");
    printf("-i <filename> : Input Data file\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    optiga_key_id_t optiga_key_id;
    uint8_t message[2048];     //To store the signture generated
    uint16_t messagelen = sizeof(message);
    uint8_t encyptdata[2048];
    uint16_t encyptdatalen = sizeof(encyptdata);

    uint8_t pubkey[2048];
    uint32_t pubkeyLen;
    uint16_t pubkeySize;
    uint16_t pubkeyType;
    uint16_t nid = 0;

    char *outFile = NULL;
    char *inFile = NULL;
    char *pubkeyFile = NULL;
    char name[100];

    public_key_from_host_t public_key_from_host;
    optiga_rsa_encryption_scheme_t encryption_scheme;

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
        while (-1 != (option = getopt(argc, argv, "k:o:i:p:Xh")))
        {
            switch (option)
            {
                case 'k': // OID Key
                    uOptFlag.flags.enc = 1;
                    optiga_key_id = trustmHexorDec(optarg);
                    break;
                case 'o': // Output
                    uOptFlag.flags.output = 1;
                    outFile = optarg;
                    break;
                case 'i': // Input
                    uOptFlag.flags.input = 1;
                    inFile = optarg;
                    break;
                case 'p': // Host Pubkey
                    uOptFlag.flags.pubkey = 1;
                    pubkeyFile = optarg;
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
        if(uOptFlag.flags.enc == 1)
        {
            if(uOptFlag.flags.output != 1)
            {
                printf("Output filename missing!!!\n");
                break;
            }

            if(uOptFlag.flags.input != 1)
            {
                printf("Input filename missing!!!\n");
                break;
            }

            printf("OID Key          : 0x%.4X \n",optiga_key_id);
            printf("Output File Name : %s \n", outFile);
            printf("Input File Name  : %s \n", inFile);

            messagelen = trustmreadFrom(message, (uint8_t *) inFile);
            if (messagelen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            printf("Input data : \n");
            trustmHexDump(message,messagelen);

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }

            encryption_scheme = OPTIGA_RSAES_PKCS1_V15;
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_rsa_encrypt_message(me_crypt,
                                                                encryption_scheme,
                                                                message,
                                                                messagelen,
                                                                NULL,
                                                                0,
                                                                OPTIGA_CRYPT_OID_DATA,
                                                                &optiga_key_id,
                                                                encyptdata,
                                                                &encyptdatalen);
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
                trustmwriteTo(encyptdata, encyptdatalen, outFile);
                printf("Success\n");
            }
        }

        if(uOptFlag.flags.pubkey == 1)
        {
            if(uOptFlag.flags.output != 1)
            {
                printf("Output filename missing!!!\n");
                break;
            }

            if(uOptFlag.flags.input != 1)
            {
                printf("Input filename missing!!!\n");
                break;
            }

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
            if ((pubkeyType != EVP_PKEY_RSA) && (pubkeyType != EVP_PKEY_RSA2))
            {
                printf("Wrong Key Type!!!\n");
                break;
            }

            printf("Pubkey file      : %s \n",pubkeyFile);
            printf("Output File Name : %s \n", outFile);
            printf("Input File Name  : %s \n", inFile);

            messagelen = trustmreadFrom(message, (uint8_t *) inFile);
            if (messagelen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            printf("Input data : \n");
            trustmHexDump(message,messagelen);

            encryption_scheme = OPTIGA_RSAES_PKCS1_V15;
            public_key_from_host.public_key = pubkey;
            public_key_from_host.length = pubkeyLen;

            if(pubkeySize == 1024)
                public_key_from_host.key_type = (uint8_t)OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
            else
                public_key_from_host.key_type = (uint8_t)OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_rsa_encrypt_message(me_crypt,
                                                                encryption_scheme,
                                                                message,
                                                                messagelen,
                                                                NULL,
                                                                0,
                                                                OPTIGA_CRYPT_HOST_DATA,
                                                                &public_key_from_host,
                                                                encyptdata,
                                                                &encyptdatalen);
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
                trustmwriteTo(encyptdata, encyptdatalen, outFile);
                printf("Success\n");
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
