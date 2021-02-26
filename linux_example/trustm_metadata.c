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

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

static const uint8_t __bALW[] = {0x01,0x00}; // alway read or write
static const uint8_t __bNEV[] = {0x01,0xff}; // disable read or write
static const uint8_t __bON_IN[] = {0x03,0xE1,0xFC,0x03}; // disable on IN
static const uint8_t __bON_OP[] = {0x03,0xE1,0xFC,0x07}; // disable on OP
static const uint8_t __bON_TE[] = {0x03,0xE1,0xFC,0xFF}; // disable on TE
static const uint8_t __bIN[] = {0x01,0x03}; // Set LcsO to Initialzation State
static const uint8_t __bOP[] = {0x01,0x07}; // Set LcsO to Operational State
static const uint8_t __bTE[] = {0x01,0x0F}; // Set LcsO to Termination State

typedef struct _OPTFLAG {
    uint16_t    read        : 1;
    uint16_t    write       : 1;
    uint16_t    lcschange   : 1;
    uint16_t    lcsread     : 1;
    uint16_t    lcsexecute  : 1;
    uint16_t    lcsin       : 1;
    uint16_t    lcsop       : 1;
    uint16_t    lcste       : 1;
    uint16_t    custom      : 1;
    uint16_t    bypass      : 1;
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

static void _helpmenu(void)
{
    printf("\nHelp menu: trustm_metadata <option> ...<option>\n");
    printf("option:- \n");
    printf("-r <OID>  : Read metadata of OID 0xNNNN \n");
    printf("-w <OID>  : Write metadata of OID\n");
    printf("-C <data> : Set Change mode (a:ALW,\n");
    printf("                             n:NEV,\n");
    printf("                             i:Lsc0 < 0x03,\n");
    printf("                             o:Lsc0 < 0x07,\n");
    printf("                             t:Lsc0 < 0xFF,\n");
    printf("                             f:<input file for complex setting>)\n");
    printf("-R <data> : Set Read mode   (a:ALW,\n");
    printf("                             n:NEV,\n");
    printf("                             i:Lsc0 < 0x03,\n");
    printf("                             o:Lsc0 < 0x07,\n");
    printf("                             t:Lsc0 < 0xFF,\n");
    printf("                             f:<input file for complex setting>)\n");
    printf("-E <data> : Set Change mode (a:ALW,\n");
    printf("                             n:NEV,\n");
    printf("                             i:Lsc0 < 0x03,\n");
    printf("                             o:Lsc0 < 0x07,\n");
    printf("                             t:Lsc0 < 0xFF,\n");
    printf("                             f:<input file for complex setting>)\n");
    printf("-F <file> : Custom input\n");
    printf("          : (Need to input the full Metadata to be written)\n");
    printf("-I        : Set Initialization State (Lsc0: 0x03)\n");
    printf("-O        : Set Operational State (Lsc0: 0x07)\n");
    printf("-T        : Set Termination State (Lsc0: 0xFF)\n");
    printf("-X        : Bypass Shielded Communication \n");
    printf("-h        : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint16_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t mode[200];
    uint16_t modeLen;
    uint8_t *lcsChange = NULL;
    uint8_t *lcsRead = NULL;
    uint8_t *lcsExecute = NULL;
    uint8_t *customSetting = NULL;
    uint8_t tempData[20];

    char    messagebuf[500];

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
        while (-1 != (option = getopt(argc, argv, "r:w:C:R:E:IOTF:Xh")))
        {
            switch (option)
            {
                case 'r': // Read
                    uOptFlag.flags.read = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'w': // Write
                    uOptFlag.flags.write = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'C': // Change setting
                    uOptFlag.flags.lcschange = 1;
                    lcsChange = (uint8_t *)optarg;
                    if((lcsChange[0] != 'a')&&(lcsChange[0] != 'n')&&
                        (lcsChange[0] != 'i')&&(lcsChange[0] != 'o')&&
                        (lcsChange[0] != 't')&&(lcsChange[0] != 'f'))
                    {
                        _helpmenu();
                        exit(0);
                    }
                    break;
                case 'R': // Read setting
                    uOptFlag.flags.lcsread = 1;
                    lcsRead = (uint8_t *)optarg;
                    if((lcsRead[0] != 'a')&&(lcsRead[0] != 't')&&
                        (lcsRead[0] != 'i')&&(lcsRead[0] != 'o')&&
                        (lcsRead[0] != 'n')&&(lcsRead[0] != 'f'))
                    {
                        _helpmenu();
                        exit(0);
                    }
                    break;
                case 'E': // Execute setting
                    uOptFlag.flags.lcsexecute = 1;
                    lcsExecute = (uint8_t *)optarg;
                    if((lcsExecute[0] != 'a')&&(lcsExecute[0] != 'n')&&
                        (lcsExecute[0] != 'i')&&(lcsExecute[0] != 'o')&&
                        (lcsExecute[0] != 't')&&(lcsExecute[0] != 'f'))
                    {
                        _helpmenu();
                        exit(0);
                    }
                    break;
                case 'I': // IN
                    uOptFlag.flags.lcsin = 1;
                    break;
                case 'O': // OP
                    uOptFlag.flags.lcsop = 1;
                    break;
                case 'T': // TE
                    uOptFlag.flags.lcste = 1;
                    break;
                case 'F': // Custom Setting
                    uOptFlag.flags.custom = 1;
                    customSetting = (uint8_t *)optarg;
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
    if (return_status != OPTIGA_LIB_SUCCESS) {exit(1);}

    trustmGetOIDName(optiga_oid, messagebuf);
    printf("========================================================\n");
    puts(messagebuf);

    do
    {
        if((uOptFlag.flags.read != 1)&&(uOptFlag.flags.write != 1))
        {
            printf("Must at least contain input -r  or -w\n");
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
            return_status = optiga_util_read_metadata(me_util,
                                                        optiga_oid,
                                                        read_data_buffer,
                                                        &bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
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

        if(uOptFlag.flags.write == 1)
        {
            if ((uOptFlag.flags.lcsin != 1)&&(uOptFlag.flags.lcsop != 1)&&(uOptFlag.flags.lcste != 1)&&
                (uOptFlag.flags.custom != 1)&&(uOptFlag.flags.lcschange != 1)&&
                (uOptFlag.flags.lcsexecute != 1)&&(uOptFlag.flags.lcsread != 1))
            {
                printf ("\nMust at least contain input -F,-I,-O,-T,-C,-R or -E!!! \n");
                exit(1);
            }

            if (uOptFlag.flags.custom == 1)
            {
                modeLen=0;
                modeLen = trustmreadFrom(tempData, customSetting);
                memcpy(mode,tempData,modeLen);
            }
            else
            {
                modeLen=0;
                mode[modeLen++] = 0x20;
                modeLen++; // skip the len input first
                if ((uOptFlag.flags.lcsin == 1) || (uOptFlag.flags.lcsop == 1) || (uOptFlag.flags.lcste == 1))
                {
                    mode[modeLen++] = 0xC0; // LcsO
                    if(uOptFlag.flags.lcste == 1)
                    {
                        memcpy((mode+modeLen),__bTE,sizeof(__bTE));
                        modeLen += sizeof(__bTE);
                    }
                    else if (uOptFlag.flags.lcsop == 1)
                    {
                        memcpy((mode+modeLen),__bOP,sizeof(__bOP));
                        modeLen += sizeof(__bOP);
                    }
                    else
                    {
                        memcpy((mode+modeLen),__bIN,sizeof(__bIN));
                        modeLen += sizeof(__bIN);                        
                    }
                }

                if (uOptFlag.flags.lcschange == 1)
                {
                    mode[modeLen++] = 0xD0; // Change Access Condition
                    switch(lcsChange[0])
                    {
                        case 'a':
                            memcpy((mode+modeLen),__bALW,sizeof(__bALW));
                            modeLen += sizeof(__bALW);
                            break;
                        case 'n':
                            memcpy((mode+modeLen),__bNEV,sizeof(__bNEV));
                            modeLen += sizeof(__bNEV);
                            break;
                        case 'i':
                            memcpy((mode+modeLen),__bON_IN,sizeof(__bON_IN));
                            modeLen += sizeof(__bON_IN);
                            break;
                        case 'o':
                            memcpy((mode+modeLen),__bON_OP,sizeof(__bON_OP));
                            modeLen += sizeof(__bON_OP);
                            break;
                        case 't':
                            memcpy((mode+modeLen),__bON_TE,sizeof(__bON_TE));
                            modeLen += sizeof(__bON_TE);
                            break;
                        case 'f':
                            if (lcsChange[1] == ':')
                            {
                                trustmreadFrom(tempData, (lcsChange+2));
                                if((tempData[0]+1) < 0x0b)
                                {
                                    memcpy((mode+modeLen),tempData,(tempData[0]+1));
                                    modeLen += (tempData[0]+1);
                                }
                                else
                                {
                                    printf ("\nInvalid input!!! \n");
                                    exit(1);
                                }
                            }
                            else
                            {
                                printf ("\nInvalid f parameter input!!! \n");
                                exit(1);
                            }
                            break;
                    }
                }

                if (uOptFlag.flags.lcsread == 1)
                {
                    mode[modeLen++] = 0xD1; // Read Access Condition
                    switch(lcsRead[0])
                    {
                        case 'a':
                            memcpy((mode+modeLen),__bALW,sizeof(__bALW));
                            modeLen += sizeof(__bALW);
                            break;
                        case 'n':
                            memcpy((mode+modeLen),__bNEV,sizeof(__bNEV));
                            modeLen += sizeof(__bNEV);
                            break;
                        case 'i':
                            memcpy((mode+modeLen),__bON_IN,sizeof(__bON_IN));
                            modeLen += sizeof(__bON_IN);
                            break;
                        case 'o':
                            memcpy((mode+modeLen),__bON_OP,sizeof(__bON_OP));
                            modeLen += sizeof(__bON_OP);
                            break;
                        case 't':
                            memcpy((mode+modeLen),__bON_TE,sizeof(__bON_TE));
                            modeLen += sizeof(__bON_TE);
                            break;
                        case 'f':
                            if (lcsRead[1] == ':')
                            {
                                trustmreadFrom(tempData, (lcsRead+2));
                                if((tempData[0]+1) < 0x0b)
                                {
                                    memcpy((mode+modeLen),tempData,(tempData[0]+1));
                                    modeLen += (tempData[0]+1);
                                }
                                else
                                {
                                    printf ("\nInvalid input!!! \n");
                                    exit(1);
                                }
                            }
                            else
                            {
                                printf ("\nInvalid f parameter input!!! \n");
                                exit(1);
                            }
                            break;
                    }
                }

                if (uOptFlag.flags.lcsexecute == 1)
                {
                    mode[modeLen++] = 0xD3; // Execute Access Condition
                    switch(lcsExecute[0])
                    {
                        case 'a':
                            memcpy((mode+modeLen),__bALW,sizeof(__bALW));
                            modeLen += sizeof(__bALW);
                            break;
                        case 'n':
                            memcpy((mode+modeLen),__bNEV,sizeof(__bNEV));
                            modeLen += sizeof(__bNEV);
                            break;
                        case 'i':
                            memcpy((mode+modeLen),__bON_IN,sizeof(__bON_IN));
                            modeLen += sizeof(__bON_IN);
                            break;
                        case 'o':
                            memcpy((mode+modeLen),__bON_OP,sizeof(__bON_OP));
                            modeLen += sizeof(__bON_OP);
                            break;
                        case 't':
                            memcpy((mode+modeLen),__bON_TE,sizeof(__bON_TE));
                            modeLen += sizeof(__bON_TE);
                            break;
                        case 'f':
                            if (lcsExecute[1] == ':')
                            {
                                trustmreadFrom(tempData, (lcsExecute+2));
                                if((tempData[0]+1) < 0x0b)
                                {
                                    memcpy((mode+modeLen),tempData,(tempData[0]+1));
                                    modeLen += (tempData[0]+1);
                                }
                                else
                                {
                                    printf ("\nInvalid input!!! \n");
                                    exit(1);
                                }
                            }
                            else
                            {
                                printf ("\nInvalid f parameter input!!! \n");
                                exit(1);
                            }
                            break;
                    }
                }
                mode[1] = modeLen-2;
            }

            printf("\n");
            trustmHexDump(mode,modeLen);
            printf("\t");
            trustmdecodeMetaData(mode);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_write_metadata(me_util,
                                                        optiga_oid,
                                                        mode,
                                                        modeLen);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
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
