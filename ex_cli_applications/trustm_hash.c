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
#include <sys/time.h>

#include "ifx_i2c_config.h"
#include "optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>


typedef struct _OPTFLAG {
    uint16_t    hash        : 1;
    uint16_t    input       : 1;
    uint16_t    output      : 1;
    uint16_t    bypass      : 1;
    uint16_t    dummy4      : 1;
    uint16_t    dummy5      : 1;
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
    printf("\nHelp menu: trustm_hash <option> ...<option>\n");
    printf("option:- \n");
    printf("-o <filename> : Output to file \n");
    printf("-i <filename> : Input Data file\n");
    printf("-H            : Hash with SHA256\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    optiga_hash_context_t hash_context;
    hash_data_from_host_t hash_data_host;
    uint8_t hash_context_buffer[2048];

    uint8_t digest[32];
    uint16_t digestLen = 0;
    uint8_t data[2048];
    uint16_t dataLen = 0;

    char *outFile = NULL;
    char *inFile = NULL;
    FILE *fp = NULL;
    uint16_t filesize;

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
        while (-1 != (option = getopt(argc, argv, "o:i:HXh")))
        {
            switch (option)
            {
                case 'o': // Output
                    uOptFlag.flags.output = 1;
                    outFile = optarg;
                    break;
                case 'i': // Input
                    uOptFlag.flags.input = 1;
                    inFile = optarg;
                    break;
                case 'H': // Input
                    uOptFlag.flags.hash = 1;
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

        printf("Output File Name : %s \n", outFile);
        printf("Input File Name  : %s \n", inFile);
        // Start performance timer
        gettimeofday(&start, NULL);
        if(uOptFlag.flags.hash == 1)
        {
            //open
            fp = fopen((const char *)inFile,"rb");
            if (!fp)
            {
                printf("error opening file : %s\n",inFile);
                exit(1);
            }

            hash_context.context_buffer = hash_context_buffer;
            hash_context.context_buffer_length = sizeof(hash_context_buffer);
            hash_context.hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;
            filesize = 0;

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_COMMAND_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_hash_start(me_crypt, &hash_context);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;

            while((dataLen = fread(data,1,sizeof(data),fp)) > 0)
            {
                hash_data_host.buffer = data;
                hash_data_host.length = dataLen;

                if(uOptFlag.flags.bypass != 1)
                {
                    // OPTIGA Comms Shielded connection settings to enable the protection
                    OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                    OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_COMMAND_PROTECTION);
                }

                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_crypt_hash_update(me_crypt,
                                                        &hash_context,
                                                        OPTIGA_CRYPT_HOST_DATA,
                                                        &hash_data_host);
                if (OPTIGA_LIB_SUCCESS != return_status)
                    break;
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;
                filesize += dataLen;
            }

            // Capture OPTIGA Trust M error
            if (return_status != OPTIGA_LIB_SUCCESS)
            {
                trustmPrintErrorCode(return_status);
                break;
            }

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_COMMAND_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_hash_finalize(me_crypt,
                                                       &hash_context,
                                                       digest);
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
                printf("filesize: %d\n",filesize);
                digestLen = sizeof(digest);
                printf("Hash Success\n");
                trustmwriteTo(digest, digestLen, outFile);
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
