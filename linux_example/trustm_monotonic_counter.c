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
    uint16_t    update      : 1;
    uint16_t    invalue     : 1;
    uint16_t    steps       : 1;
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
    OPTFLAG    flags;
    uint16_t    all;
} uOptFlag;

static void _helpmenu(void)
{
    printf("\nHelp menu: trustm_monotonic_counter <option> ...<option>\n");
    printf("option:- \n");
    printf("-r <OID>      : Read from OID [0xE120-0xE123] \n");
    printf("-w <OID>      : Write to OID [0xE120-0xE123] \n");
    printf("-u <OID>      : Update Counter [0xE120-0xE123] \n");
    printf("-i <value>    : Input Value \n");
    printf("-s <value>    : Increment Steps \n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint32_t inValue = 0;
    uint32_t steps = 0;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[8];
    uint32_t bytes_to_read = sizeof(read_data_buffer);
    uint8_t mode = OPTIGA_UTIL_ERASE_AND_WRITE;

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
        while (-1 != (option = getopt(argc, argv, "r:w:i:s:u:Xh")))
        {
            switch (option)
            {
                case 'r': // Read
                    uOptFlag.flags.read = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    //if((optiga_oid < 0xE120) || (optiga_oid > 0xE123))
                    //{
                    //    printf("Invalid Monotonic Counter OID!!!\n");
                    //    exit(0);
                    //}
                    break;
                case 'w': // Write
                    uOptFlag.flags.write = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    //if((optiga_oid < 0xE120) || (optiga_oid > 0xE123))
                    //{
                    //    printf("Invalid Monotonic Counter OID!!!\n");
                    //    exit(0);
                    //}
                    break;
                case 'u': // Update
                    uOptFlag.flags.update = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    //if((optiga_oid < 0xE120) || (optiga_oid > 0xE123))
                    //{
                    //    printf("Invalid Monotonic Counter OID!!!\n");
                    //    exit(0);
                    //}
                    break;
                case 'i': // Input Value
                    uOptFlag.flags.invalue = 1;
                    inValue = trustmHexorDec(optarg);
                    break;
                case 's': // output Increment Steps
                    uOptFlag.flags.steps = 1;
                    steps = trustmHexorDec(optarg);
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
        trustm_hybernate_flag = 1; // Enable Hybernate Context Save
    else
        trustm_hybernate_flag = 0; // disable Hybernate Context Save

    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS) {exit(1);}

    printf("========================================================\n");

    do
    {
        if(uOptFlag.flags.update)
        {
            if(uOptFlag.flags.steps != 1)
            {
                printf("No steps Value.\n");
                break;
            }

            printf("Steps Value : %d [0x%.8X]\n", steps, steps);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_update_count(me_util,
                                                     optiga_oid,
                                                     steps);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
                printf("Update Counter Success.\n");
        }

       if(uOptFlag.flags.write == 1)
       {
            if(uOptFlag.flags.invalue != 1)
            {
                printf("No input Value.\n");
                break;
            }

            printf("Input Value : %d [0x%.8X]\n", inValue, inValue);
            read_data_buffer[0] = 0;
            read_data_buffer[1] = 0;
            read_data_buffer[2] = 0;
            read_data_buffer[3] = 0;
            read_data_buffer[4] = (uint8_t) ((inValue & 0xff000000) >> 24);
            read_data_buffer[5] = (uint8_t) ((inValue & 0x000ff0000) >> 16);
            read_data_buffer[6] = (uint8_t) ((inValue & 0x0000ff00) >> 8);
            read_data_buffer[7] = (uint8_t) inValue & 0x000000ff;

            trustmHexDump(read_data_buffer, bytes_to_read);

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
                                                    0,
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
                                                0,
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
                inValue = (uint32_t)((read_data_buffer[4]<<24) + (read_data_buffer[5]<<16)
                            + (read_data_buffer[6]<<8) + (read_data_buffer[7]));

                printf("Monotonic Counter x : [0x%.4X]\n", optiga_oid);
                printf("Threshold           : 0x%.2X%.2X%.2X%.2X [%d]\n",read_data_buffer[4],
                                                                        read_data_buffer[5],
                                                                        read_data_buffer[6],
                                                                        read_data_buffer[7],
                                                                        inValue);
                inValue = (uint32_t)((read_data_buffer[0]<<24) + (read_data_buffer[1]<<16)
                            + (read_data_buffer[2]<<8) + (read_data_buffer[3]));

                printf("Counter Value       : 0x%.2X%.2X%.2X%.2X [%d]\n",read_data_buffer[0],
                                                                        read_data_buffer[1],
                                                                        read_data_buffer[2],
                                                                        read_data_buffer[3],
                                                                        inValue);
            }
       }
    } while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hybernate_flag = 0; // Disable Hybernate Context Save
    return 0;
}
