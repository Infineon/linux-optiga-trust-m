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
#include <openssl/asn1.h>


typedef struct _OPTFLAG {
        uint16_t        type            : 1;
        uint16_t        keysize         : 1;
        uint16_t        bypass          : 1;
        uint16_t        dummy3          : 1;
        uint16_t        dummy4          : 1;
        uint16_t        dummy5          : 1;
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
    printf("\nHelp menu: trustm_symmetric_keygen <option> ...<option>\n");
    printf("option:- \n");
    printf("-t <key type>   : Key type Auth:0x01 Enc :0x02 HFWU:0x04\n");
    printf("                           DevM:0X08 Sign:0x10 Agmt:0x20\n");
    printf("                           [default Enc]\n");
    printf("-k <key size>   : Key size AES128:0x81 AES192:0x82 AES256:0x83\n");
    printf("                           [default AES128]\n");
    printf("-X              : Bypass Shielded Communication \n");
    printf("-h              : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    optiga_key_id_t symmetric_key;                            
    uint8_t keyType=0x02;// default Enc
    optiga_symmetric_key_type_t keySize=0x81;// default 128

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
        while (-1 != (option = getopt(argc, argv, "t:k:Xh")))
        {
            switch (option)
            {

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
                        uOptFlag.flags.keysize = 1;
                        keySize = trustmHexorDec(optarg);
                        if ((keySize != 0x81) && (keySize != 0x82)&& (keySize != 0x83))
                        {
                                printf("Key Size Error!!!\n");
                                exit(0);
                        }
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
            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
            
            optiga_lib_status = OPTIGA_LIB_BUSY;
            symmetric_key = OPTIGA_KEY_ID_SECRET_BASED;
            return_status = optiga_crypt_symmetric_generate_key(me_crypt,
                                                            keySize,
                                                            keyType,
                                                            FALSE,
                                                            &symmetric_key);
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
                printf("Successfully Generated Symmetric Key in 0xE200 \n");
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
