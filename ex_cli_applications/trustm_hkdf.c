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

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>


typedef struct _OPTFLAG {
        uint16_t        read            : 1;
        uint16_t        type            : 1;
        uint16_t        output          : 1;
        uint16_t        info            : 1;
        uint16_t        salt            : 1;
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
    printf("\nHelp menu: trustm_hkdf <option> ...<option>\n");
    printf("option:- \n");
    printf("-i <OID>      : Input secret OID 0xNNNN \n");
    printf("                [default 0xF1D0]\n");
    printf("-H <SHA>      : SHA256:0x08 SHA384 :0x09 SHA512:0x0A\n");
    printf("                [default SHA256]\n");
    printf("-f <filename> : Import Info \n");
    printf("-s <filename> : Import Salt \n");
    printf("-o <filename> : Export Derived Key \n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    uint16_t optiga_oid;
    uint8_t decryption_key [16] = {0};

    uint8_t hkdf_type=0x08;// default SHA256
    optiga_oid=0xF1D0;// default OID
    uint8_t salt[64];     
    uint16_t saltlen = sizeof(salt);
    uint8_t info[64];     
    uint16_t infolen = sizeof(info);
    
    char *outFile = NULL;
    char *infoFile = NULL;
    char *saltFile = NULL;
    
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
        while (-1 != (option = getopt(argc, argv, "i:H:o:f:s:Xh")))
        {
            switch (option)
            {
                
                case 'i': // Input Secret ID
                        uOptFlag.flags.read = 1;
                        optiga_oid = trustmHexorDec(optarg);
                        printf("Input Secret OID: 0x%.4X\n",optiga_oid);
                        /*if((optiga_oid < 0xF1D0) || (optiga_oid > 0xF1DB))
                        {
                                printf("Invalid Input Secret OID!!!\n");
                                exit(0);
                        }*/
                        break;
                case 'H': // Save pubkey
                        uOptFlag.flags.type = 1;
                        hkdf_type = trustmHexorDec(optarg);
                        printf("HKDF Type 0x%.4X\n",hkdf_type);
                        break;
                case 'f': // Info
                        uOptFlag.flags.info = 1;
                        infoFile = optarg;
                        break;
                    
                case 's': // Salt
                        uOptFlag.flags.salt = 1;
                        saltFile = optarg;
                        break;
                case 'o': // export Derived Key
                        uOptFlag.flags.output = 1;
                        outFile = optarg;
                        printf("Output Derived key. \n");
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
            
            if(uOptFlag.flags.info != 1)
            {
                printf("Info filename missing!!!\n");
                break;
            }
            
            if(uOptFlag.flags.salt != 1)
            {
                printf("Salt filename missing!!!\n");
                break;
            }

            printf("HKDF Type        : 0x%.4X \n",hkdf_type);
            printf("Info File Name   : %s \n", infoFile);
            printf("Salt File Name   : %s \n", saltFile);   
            printf("Output File Name : %s \n", outFile);   
            
            saltlen = trustmreadFrom(salt, (uint8_t *) saltFile);
            if (saltlen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            printf("salt data : \n");
            trustmHexDump(salt,saltlen);
            
            infolen = trustmreadFrom(info, (uint8_t *) infoFile);
            if (infolen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            printf("Info data : \n");
            trustmHexDump(info,infolen);

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            { 
            // OPTIGA Comms Shielded connection settings to enable the protection
            OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
            OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
            
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_hkdf(me_crypt,
                                          hkdf_type,
                                          optiga_oid, /* Input secret OID */
                                          salt,
                                          saltlen, //sizeof(salt),
                                          info,
                                          infolen,  //sizeof(info),
                                          sizeof(decryption_key),
                                          TRUE,
                                          decryption_key);
                                          
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

                printf("Success\n");
                printf("Decryption Key :\n");
                trustmHexDump(decryption_key, (uint32_t) sizeof(decryption_key));

                return_status = trustmwriteTo(decryption_key,sizeof(decryption_key),outFile);
                if (return_status != OPTIGA_LIB_SUCCESS)
                {
                    printf("Error when saving file!!!\n");
                }
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
