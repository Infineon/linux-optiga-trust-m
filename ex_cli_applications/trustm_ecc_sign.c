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
#include <openssl/ecdsa.h>
#include <openssl/evp.h>


#define MAX_OID_PUB_CERT_SIZE   1728

typedef struct _OPTFLAG {
    uint16_t    sign        : 1;
    uint16_t    input       : 1;
    uint16_t    output      : 1;
    uint16_t    outputssl   : 1;
    uint16_t    hash        : 1;
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
    printf("\nHelp menu: trustm_ecc_sign <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID Key>  : Select ECC key for signing OID (0xE0F0-0xE0F3) \n");
    printf("-o <filename> : Output to file with header\n");
    printf("-O <filename> : Output to file without header\n");    
    printf("-i <filename> : Input Data file\n");
    printf("-H <HashAlgo> : SHA256:sha256 SHA384:sha384 SHA512:sha512\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    optiga_key_id_t optiga_key_id;
    char hash_algo[20] ="sha256";
    struct timeval start;
    struct timeval end;
    double time_taken;
    uint8_t signature [150];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);
    uint8_t digest[64];
    unsigned int digestLen=0;
    char *outFile = NULL;
    char *inFile = NULL;
    FILE *fp = NULL;
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
        while (-1 != (option = getopt(argc, argv, "k:o:O:i:H::Xh")))
        {
            switch (option)
            {
                case 'k': // OID Key
                    uOptFlag.flags.sign = 1;
                    optiga_key_id = trustmHexorDec(optarg);
                    break;
                case 'o': // Output with header
                    uOptFlag.flags.outputssl = 1;
                    outFile = optarg;
                    break;
                case 'O': // Output without header
                    uOptFlag.flags.output = 1;
                    outFile = optarg;
                    break;
                case 'i': // Input
                    uOptFlag.flags.input = 1;
                    inFile = optarg;
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
        if(uOptFlag.flags.sign == 1)
        {
            if((uOptFlag.flags.output != 1) && (uOptFlag.flags.outputssl != 1))
            {
                printf("Output filename missing!!!\n");
                break;
            }

            if(uOptFlag.flags.input != 1)
            {
                printf("Input filename missing!!!\n");
                break;
            }

            printf("OID Key          : 0x%.4X\n",optiga_key_id);
            printf("Output File Name : %s \n", outFile);
            printf("Input File Name  : %s \n", inFile);

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
                printf("Hash Success: %s\n", hash_algo);  
                trustmHexDump(digest,digestLen);		
            } else
            {
                digestLen = trustmreadFrom(digest, (uint8_t *) inFile);
                if (digestLen == 0)
                {
                    printf("Error reading file!!!\n");
                    break;
                }
                if (digestLen > sizeof(digest))
                {
                    printf("Error : File too big try using option -H \n");
                    break;
                } else
                {
                    printf("Input data[%d] : \n", digestLen);
                    trustmHexDump(digest,digestLen);
                }
            }

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
                
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_ecdsa_sign(me_crypt,
                                                    digest,
                                                    digestLen,
                                                    optiga_key_id,
                                                    signature+3,
                                                    &signature_length);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                if(uOptFlag.flags.outputssl == 1)
                {
                    if(signature_length<0x7F){
                        signature[1] = 0x30; // Insert SEQUENCE
                        signature[2] = signature_length; // insert length
                        signature_length += 2;
                        trustmwriteTo(signature+1, signature_length, outFile);
                    }
                    else{
                        
                        trustm_ecc_r_s_padding_check(signature+3, &signature_length );
                        signature[0] = 0x30; // Insert SEQUENCE
                        signature[1] = 0x81; // insert length
                        signature[2] = signature_length;
                        signature_length += 3;
                        trustmwriteTo(signature, signature_length, outFile);

                    }
                }
                // stop performance timer.
                gettimeofday(&end, NULL);
                // Calculating total time taken by the program.
                time_taken = (end.tv_sec - start.tv_sec) * 1e6;
                time_taken = (time_taken + (end.tv_usec - start.tv_usec)) * 1e-6;
                printf("OPTIGA execution time: %0.4f sec.\n", time_taken);

                //trustmwriteTo(signature, signature_length, outFile);
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
    return return_status;
}
