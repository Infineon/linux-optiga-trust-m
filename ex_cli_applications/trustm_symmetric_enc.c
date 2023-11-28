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
#include <math.h>
#include <sys/time.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"


#include "trustm_helper.h"

#define MESSAGE_FRAGMENT_LEN    16
#define PADDING_START_BYTE      0xFF


typedef struct _OPTFLAG {
    uint16_t    mode        : 1;
    uint16_t    input       : 1;
    uint16_t    output      : 1;
    uint16_t    bypass      : 1;
    uint16_t    iv          : 1;
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
    printf("\nHelp menu: trustm_symmetric_enc <option> ...<option>\n");
    printf("option:- \n");
    printf("-m <mode>     : Mode CBC:0x09 CBC_MAC:0X0A CMAC:0X0B \n");
    printf("                     [default CBC]\n");
    printf("-o <filename> : Output to file \n");
    printf("-i <filename> : Input Data file\n");
    printf("-v <filename> : Input IV Value\n");
    printf("                Only needed for CBC mode\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    uint8_t message[2048];     
    uint32_t messagelen = sizeof(message);
    uint8_t iv[64];     
    uint16_t ivlen = sizeof(iv);
    uint8_t encyptdata[64];
    uint32_t encyptdatalen = sizeof(encyptdata);

    char *outFile = NULL;
    char *inFile = NULL;
    char *ivFile = NULL;
    
    optiga_key_id_t symmetric_key;  
    optiga_symmetric_encryption_mode_t encryption_mode;
    encryption_mode = OPTIGA_SYMMETRIC_CBC;

    // 2d array to store larger data files
    uint8_t *messageFragment;
    uint8_t *encryptedFragment;

    // keeping track of fragments
    int numOfFragments = 0;


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
        while (-1 != (option = getopt(argc, argv, "m:o:i:v:Xh")))
        {
            switch (option)
            {
                case 'm': // AES Mode
                    uOptFlag.flags.mode = 1;
                    encryption_mode = trustmHexorDec(optarg);
                    break;
                case 'o': // Output
                    uOptFlag.flags.output = 1;
                    outFile = optarg;
                    break;
                case 'i': // Input
                    uOptFlag.flags.input = 1;
                    inFile = optarg;
                    break;
                case 'v': // IV
                    uOptFlag.flags.iv = 1;
                    ivFile = optarg;
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
        if(uOptFlag.flags.mode == 1)
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

            printf("mode             : 0x%.4X \n",encryption_mode);
            printf("Output File Name : %s \n", outFile);
            printf("Input File Name  : %s \n", inFile);

            messagelen = trustmreadFrom(message, (uint8_t *) inFile);
            if (messagelen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            if (messagelen > 2048)
            {
                printf("File size exceeded 2048 bytes!!!\n");
                break;
            }

            printf("Input data : \n");
            trustmHexDump(message,messagelen);
            if (encryption_mode == OPTIGA_SYMMETRIC_CBC){
                printf("IV File Name  : %s \n", ivFile);
                ivlen = trustmreadFrom(iv, (uint8_t *) ivFile);
            if(ivlen == 0)
            {
                printf("Error reading file!!!\n");
                break;
            }

            printf("Initialized value : \n");
            trustmHexDump(iv,ivlen);}

            // if the message size is more than 16 bytes
            int i;
                // calculate total number of fragments needed
            numOfFragments = messagelen / MESSAGE_FRAGMENT_LEN + ((messagelen % MESSAGE_FRAGMENT_LEN) != 0);

            // extra padding if the data is already block-aligned to 16 bytes
            if (messagelen % MESSAGE_FRAGMENT_LEN == 0) 
            {
                numOfFragments += 1;
            }

            printf("Number of fragments: %d\n", numOfFragments);
            printf("Total data length: %d\n", messagelen);
                

            // allocating memeory
            messageFragment = (uint8_t*) calloc(numOfFragments * MESSAGE_FRAGMENT_LEN, sizeof(uint8_t));
            encryptedFragment = (uint8_t*) calloc(numOfFragments * MESSAGE_FRAGMENT_LEN, sizeof(uint8_t));      

            // copying whole data file into fragments
            int bytesToRead = messagelen;

            for (i = 0; i < messagelen / MESSAGE_FRAGMENT_LEN + ((messagelen % MESSAGE_FRAGMENT_LEN) != 0); i++) {
                if (bytesToRead > MESSAGE_FRAGMENT_LEN) 
                {
                    memcpy(&messageFragment[MESSAGE_FRAGMENT_LEN * i], &message[MESSAGE_FRAGMENT_LEN * i], MESSAGE_FRAGMENT_LEN);
                    bytesToRead -= MESSAGE_FRAGMENT_LEN;
                }
                    
                else 
                {
                        memcpy(&messageFragment[MESSAGE_FRAGMENT_LEN * i], &message[MESSAGE_FRAGMENT_LEN * i], bytesToRead);
                }
            }

            // add padding start byte
            if (messagelen % MESSAGE_FRAGMENT_LEN == 0) 
            {
                messageFragment[i * MESSAGE_FRAGMENT_LEN] = PADDING_START_BYTE;
            }

            else 
            {
                messageFragment[(i - 1) * MESSAGE_FRAGMENT_LEN + bytesToRead] = PADDING_START_BYTE;
            }
            
            printf("Input data after padding:\n");
            trustmHexDump(messageFragment, MESSAGE_FRAGMENT_LEN * numOfFragments);
            
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

            if (messagelen >= MESSAGE_FRAGMENT_LEN) {
                // keeping track of each fragment
                int fragmentCounter;

                // start fragment
                optiga_lib_status = OPTIGA_LIB_BUSY;
                if(encryption_mode == OPTIGA_SYMMETRIC_CBC){
                    return_status = optiga_crypt_symmetric_encrypt_start(me_crypt,
                                                             encryption_mode,
                                                             symmetric_key,
                                                             &messageFragment[0],
                                                             MESSAGE_FRAGMENT_LEN,
                                                             iv,
                                                             ivlen,
                                                             NULL,
                                                             0,
                                                             0,
                                                             encyptdata,
                                                             &encyptdatalen);}
                else{
                    return_status = optiga_crypt_symmetric_encrypt_start(me_crypt,
                                                             encryption_mode,
                                                             symmetric_key,
                                                             &messageFragment[0],
                                                             MESSAGE_FRAGMENT_LEN,
                                                             NULL,
                                                             0,
                                                             NULL,
                                                             0,
                                                             MESSAGE_FRAGMENT_LEN * numOfFragments,
                                                             encyptdata,
                                                             &encyptdatalen);}
                if (OPTIGA_LIB_SUCCESS != return_status)
                {
                    break;
                }
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                {
                    break;
                }

                if (encyptdatalen != MESSAGE_FRAGMENT_LEN)
                {
                    printf("Encryption failed. Exiting...\n");
                    break;
                }

                // copy encrypted data
                memcpy(&encryptedFragment[0], encyptdata, encyptdatalen);

                // continue fragments
                for (fragmentCounter = 1; fragmentCounter < numOfFragments - 1; fragmentCounter++) {
                    optiga_lib_status = OPTIGA_LIB_BUSY;
                    
                    return_status = optiga_crypt_symmetric_encrypt_continue(me_crypt,
                                                             &messageFragment[fragmentCounter * MESSAGE_FRAGMENT_LEN],
                                                             MESSAGE_FRAGMENT_LEN,
                                                             encyptdata,
                                                             &encyptdatalen);
                     
                    if (OPTIGA_LIB_SUCCESS != return_status)
                    {
                        trustmPrintErrorCode(return_status);
                        exit(1);
                    }
                    //Wait until the optiga_util_read_metadata operation is completed
                    while (OPTIGA_LIB_BUSY == optiga_lib_status);
                    return_status = optiga_lib_status;
                    if (return_status != OPTIGA_LIB_SUCCESS)
                    { 
                        trustmPrintErrorCode(return_status);
                        trustm_Close();
                        exit(1);
                    }

                    if (encyptdatalen != MESSAGE_FRAGMENT_LEN)
                    {
                        printf("Encryption failed. Exiting...\n");
                        trustm_Close();
                        exit(1);
                    }

                    // copy encrypted data
                    memcpy(&encryptedFragment[fragmentCounter * MESSAGE_FRAGMENT_LEN], encyptdata, encyptdatalen);
                }

                // final fragment
                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_crypt_symmetric_encrypt_final(me_crypt,
                                                             &messageFragment[fragmentCounter * MESSAGE_FRAGMENT_LEN],
                                                             MESSAGE_FRAGMENT_LEN,
                                                             encyptdata,
                                                             &encyptdatalen);

                if (OPTIGA_LIB_SUCCESS != return_status)
                {
                    break;
                }
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                {
                    break;
                }

                if (encyptdatalen != MESSAGE_FRAGMENT_LEN)
                {
                    printf("Encryption failed. Exiting...\n");
                    break;
                }

                else
                {
                    // stop performance timer.
                    gettimeofday(&end, NULL);
                    // Calculating total time taken by the program.
                    time_taken = (end.tv_sec - start.tv_sec) * 1e6;
                    time_taken = (time_taken + (end.tv_usec - start.tv_usec)) * 1e-6;
                    printf("OPTIGA execution time: %0.4f sec.\n", time_taken);

                    // copy encrypted data
                    memcpy(&encryptedFragment[fragmentCounter * MESSAGE_FRAGMENT_LEN], encyptdata, encyptdatalen);

                    // writing everything to output file
                    trustmwriteTo(encryptedFragment, numOfFragments * MESSAGE_FRAGMENT_LEN, outFile);
                    printf("Success\n");
                }        

                // free everything
                free(messageFragment);
                free(encryptedFragment);
            }


            else {
                optiga_lib_status = OPTIGA_LIB_BUSY;
                if(encryption_mode == OPTIGA_SYMMETRIC_CBC){
                    return_status = optiga_crypt_symmetric_encrypt(me_crypt,
                                                             encryption_mode,
                                                             symmetric_key,
                                                             messageFragment,
                                                             MESSAGE_FRAGMENT_LEN,
                                                             iv,
                                                             ivlen,
                                                             NULL,
                                                             0,
                                                             encyptdata,
                                                             &encyptdatalen);}
                else{
                    return_status = optiga_crypt_symmetric_encrypt(me_crypt,
                                                             encryption_mode,
                                                             symmetric_key,
                                                             messageFragment,
                                                             MESSAGE_FRAGMENT_LEN,
                                                             NULL,
                                                             0,
                                                             NULL,
                                                             0,
                                                             encyptdata,
                                                             &encyptdatalen);}
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
        }

    }while(FALSE);


    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        trustmPrintErrorCode(return_status);

        // free everything
        free(messageFragment);
        free(encryptedFragment);
    }

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return return_status;
}
