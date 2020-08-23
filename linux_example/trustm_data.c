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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

typedef struct _OPTFLAG {
    uint16_t    read        : 1;
    uint16_t    write       : 1;
    uint16_t    infile      : 1;
    uint16_t    outfile     : 1;
    uint16_t    offset      : 1;
    uint16_t    erase       : 1;
    uint16_t    bypass      : 1;
    uint16_t    invalue     : 1;
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
    OPTFLAG    flags;
    uint16_t    all;
} uOptFlag;

static void _helpmenu(void)
{
    printf("\nHelp menu: trustm_data <option> ...<option>\n");
    printf("option:- \n");
    printf("-r <OID>      : Read from OID 0xNNNN \n");
    printf("-w <OID>      : Write to OID\n");
    printf("-i <filename> : Input file \n");
    printf("-I <value>    : Input byte value \n");
    printf("-o <filename> : Output file \n");
    printf("-p <offset>   : Offset position \n");
    printf("-e            : Erase and wirte \n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint16_t offset =0;
    uint32_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t mode = OPTIGA_UTIL_WRITE_ONLY;

    char    messagebuf[500];

    char *outFile = NULL;
    char *inFile = NULL;
    uint8_t invalue = 0;

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
        while (-1 != (option = getopt(argc, argv, "r:w:i:I:o:p:eXh")))
        {
            switch (option)
            {
                case 'r': // Read Cert
                    uOptFlag.flags.read = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'w': // Write Cert
                    uOptFlag.flags.write = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'i': // Input filename
                    uOptFlag.flags.infile = 1;
                    inFile = optarg;
                    break;
                case 'I': // Input value
                    uOptFlag.flags.invalue = 1;
                    invalue = trustmHexorDec(optarg);
                    break;
                case 'o': // output filename
                    uOptFlag.flags.outfile = 1;
                    outFile = optarg;
                    break;
                case 'p': // offset position
                    uOptFlag.flags.offset = 1;
                    offset = trustmHexorDec(optarg);
                    break;
                case 'e': // erase
                    uOptFlag.flags.erase = 1;
                    mode = OPTIGA_UTIL_ERASE_AND_WRITE;
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
    if((uOptFlag.flags.read != 1) && (uOptFlag.flags.write != 1))
    {
        printf("At least  -r or -w option must be selected.\n");
        exit(1);
    }

    if(uOptFlag.flags.bypass != 1)
        trustm_hibernate_flag = 1; // Enable hibernate Context Save
    else
        trustm_hibernate_flag = 0; // disable hibernate Context Save

    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(1);

    trustmGetOIDName(optiga_oid, messagebuf);
    printf("========================================================\n");
    printf(messagebuf);

    do
    {
        if(uOptFlag.flags.read == 1)
        {
            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            bytes_to_read = sizeof(read_data_buffer);
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_read_data(me_util,
                                                optiga_oid,
                                                offset,
                                                read_data_buffer,
                                                (uint16_t *)&bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                printf("[Size %.4d] : ", bytes_to_read);
                if (bytes_to_read > 4)
                    printf("\n");
                trustmHexDump(read_data_buffer, bytes_to_read);

                if(uOptFlag.flags.outfile == 1)
                {
                    if (!trustmWriteDER(read_data_buffer, bytes_to_read, outFile))
                        printf("Output to %s\n",outFile);
                }
            }
        }

        if(uOptFlag.flags.write == 1)
        {
            if((uOptFlag.flags.infile != 1) && (uOptFlag.flags.invalue != 1))
            {
                printf("No input file enter or input value.\n");
                break;
            }

            if(uOptFlag.flags.infile == 1)
            {
                bytes_to_read = 0;
                trustmReadDER(read_data_buffer, &bytes_to_read, inFile);
                if (bytes_to_read <= 0)
                {
                    printf("Read file: %s error!!!", inFile);
                }
            }
            else
            {
                bytes_to_read = 1;
                read_data_buffer[0] = invalue;
            }

            printf("Offset: %d\n", offset);
            printf("Input data : \n");
            trustmHexDump(read_data_buffer,bytes_to_read);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_write_data(me_util,
                                                    optiga_oid,
                                                    mode,
                                                    offset,
                                                    read_data_buffer,
                                                    bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
                printf("Write Success.\n");
        }
    } while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return 0;
}
