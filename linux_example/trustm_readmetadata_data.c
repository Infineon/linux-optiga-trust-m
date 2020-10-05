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
#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

typedef struct _OPTFLAG {
    uint16_t    bypass      : 1;
    uint16_t    dummy1      : 1;
    uint16_t    dummy2      : 1;
    uint16_t    dummy3      : 1;
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


void helpmenu(void)
{
    printf("\nHelp menu: trustm_readmetadata_data <option> ...<option>\n");
    printf("option:- \n");
    printf("-X : Bypass Shield Communication \n");
    printf("-h : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint16_t i;

    uint16_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[1024];

    char    messagebuf[500];

    uint16_t arrayOID[] = {0xE0E0,0xE0E1,0xE0E2,0xE0E3,0xE0E8,0xE0E9,0xE0EF,
                            0xE120,0xE121,0xE122,0xE123,
                            0xE140,
                            0xF1D0,0xF1D1,0xF1D2,0xF1D3,0xF1D4,0xF1D5,
                            0xF1D6,0xF1D7,0xF1D8,0xF1D9,0xF1DA,0xF1DB,
                            0xF1E0,0xF1E1};

    int option = 0;                    // Command line option.

    uOptFlag.all = 0;

    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
        // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

        // Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "Xh")))
        {
            switch (option)
            {
                case 'X': // Bypass Shielded Communication
                    uOptFlag.flags.bypass = 1;
                    printf("Bypass Shielded Communication. \n");
                    break;
                case 'h': // Print Help Menu
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
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(1);

    for (i = 0; i < sizeof(arrayOID)/2; i++) // Limit to Obj
    {
        do
        {
            optiga_oid = arrayOID[i];
            trustmGetOIDName(optiga_oid, messagebuf);

            if(messagebuf != NULL)
            {
                printf("===========================================\n");
                printf(messagebuf);

                if(uOptFlag.flags.bypass != 1)
                {
                    // OPTIGA Comms Shielded connection settings to enable the protection
                    OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
                }

                bytes_to_read = sizeof(read_data_buffer);
                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_util_read_metadata(me_util,
                                                            optiga_oid,
                                                            read_data_buffer,
                                                            &bytes_to_read);
                if (OPTIGA_LIB_SUCCESS != return_status)
                    break;
                //Wait until the optiga_util_read_metadata operation is completed
                while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;
                else
                {
                    printf("[Size %.4d] : \n", bytes_to_read);
                    trustmHexDump(read_data_buffer,bytes_to_read);
                    printf("\t");
                    trustmdecodeMetaData(read_data_buffer);
                    printf("\n");
                }
            }
        }while(FALSE);

        // Capture OPTIGA Trust M error
        if (return_status != OPTIGA_LIB_SUCCESS)
            trustmPrintErrorCode(return_status);
    }

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return 0;
}
