/**
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
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
    uint16_t    write        : 1;
    uint16_t    infile        : 1;
    uint16_t    outfile        : 1;
    uint16_t    offset        : 1;
    uint16_t    erase        : 1;
    uint16_t    dummy6        : 1;
    uint16_t    dummy7        : 1;
    uint16_t    dummy8        : 1;
    uint16_t    dummy9        : 1;
    uint16_t    dummy10        : 1;
    uint16_t    dummy11        : 1;
    uint16_t    dummy12        : 1;
    uint16_t    dummy13        : 1;
    uint16_t    dummy14        : 1;
    uint16_t    dummy15        : 1;
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
    printf("-o <filename> : Output file \n");
    printf("-p <offset>   : Offset position \n");
    printf("-e            : Erase and wirte \n");
    printf("-h            : Print this help \n");
}

static uint32_t _ParseHexorDec(const char *aArg)
{
    uint32_t value;

    if ((strncmp(aArg, "0x",2) == 0) ||(strncmp(aArg, "0X",2) == 0))
        sscanf(aArg,"%x",&value);
    else
        sscanf(aArg,"%d",&value);

    return value;
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint16_t offset =0;
    uint32_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t mode = OPTIGA_UTIL_WRITE_ONLY;
    uint8_t skip_flag;
 
    char *outFile = NULL;
    char *inFile = NULL;
 
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
        while (-1 != (option = getopt(argc, argv, "r:w:i:o:p:eh")))
        {
            switch (option)
            {
                case 'r': // Read Cert
                    uOptFlag.flags.read = 1;
                    optiga_oid = _ParseHexorDec(optarg);                 
                    break;
                case 'w': // Write Cert
                    uOptFlag.flags.write = 1;    
                    optiga_oid = _ParseHexorDec(optarg);                                     
                    break;
                case 'i': // Input filename
                    uOptFlag.flags.infile = 1;
                    inFile = optarg;    
                    break;
                case 'o': // output filename
                    uOptFlag.flags.outfile = 1;
                    outFile = optarg;                 
                    break;                    
                case 'p': // offset position
                    uOptFlag.flags.offset = 1;
                    offset = _ParseHexorDec(optarg);
                    break;                    
                case 'e': // erase
                    uOptFlag.flags.erase = 1;
                    mode = OPTIGA_UTIL_ERASE_AND_WRITE;
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
    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(1);
    
    printf("========================================================\n");    

    skip_flag = 0;
    switch (optiga_oid)
    {
        case 0xE0C0:
            printf("Global Life Cycle Status    [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C1:
            printf("Global Security Status      [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C2:
            printf("UID                         [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0C3:
            printf("Sleep Mode Activation Delay [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C4:
            printf("Current Limitation          [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C5:
            printf("Security Event Counter      [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C6:
            printf("Max Com Buffer Size         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0E0:
            printf("Device Public Key IFX       [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0E1:
        case 0xE0E2:
        case 0xE0E3:
            printf("Device Public Key           [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0E8:
            printf("Root CA Public Key Cert1    [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0E9:
            printf("Root CA Public Key Cert2    [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0EF:
            printf("Root CA Public Key Cert8    [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;
        case 0xE0F0:
            printf("Device EC Privte Key 1         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0F1:
        case 0xE0F2:
        case 0xE0F3:
            printf("Device EC Privte Key x         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0FC:
        case 0xE0FD:
            printf("Device RSA Privte Key x         [0x%.4X] ", optiga_oid);
            break;            
        case 0xE100:
        case 0xE101:
        case 0xE102:
        case 0xE103:
            printf("Session Context x           [0x%.4X] ", optiga_oid);
            break;                    
        case 0xE120:
        case 0xE121:
        case 0xE122:
        case 0xE123:
            printf("Monotonic Counter x         [0x%.4X] ", optiga_oid);
            break;
        case 0xE140:
            printf("Shared Platform Binding Secert. [0x%.4x] ", optiga_oid);
            break;
        case 0xF1C0:
            printf("Application Life Cycle Sts  [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1C1:
            printf("Application Security Sts    [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1C2:
            printf("Application Error Codes     [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1D0:
        case 0xF1D1:
        case 0xF1D2:
        case 0xF1D3:
        case 0xF1D4:
        case 0xF1D5:
        case 0xF1D6:
        case 0xF1D7:
        case 0xF1D8:
        case 0xF1D9:
        case 0xF1DA:
        case 0xF1DB:
            printf("App DataStrucObj type 1     [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;                    
        case 0xF1E0:
        case 0xF1E1:
            printf("App DataStrucObj type 2     [0x%.4X] ", optiga_oid);
            skip_flag = 1;
            break;                        
        default:
            skip_flag = 2;
            break;
    }

    do
    {
        // OPTIGA Comms Shielded connection settings to enable the protection
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_RESPONSE_PROTECTION);        
        
        if(uOptFlag.flags.read == 1)
        {
            bytes_to_read = sizeof(read_data_buffer);
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_read_data(me_util,
                                                optiga_oid,
                                                offset,
                                                read_data_buffer,
                                                (uint16_t *)&bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                break;
            }

            while (OPTIGA_LIB_BUSY == optiga_lib_status) 
            {
                //Wait until the optiga_util_read_metadata operation is completed
            }

            if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
            {
                //Reading metadata data object failed.
                printf("Error!!! optiga_lib_status [0x%.8X]\n",optiga_lib_status);
                break;
            }
            if (return_status != OPTIGA_LIB_SUCCESS)
            {
                printf("Error!!! return_status [0x%.8X]\n",return_status);
            }
            else
            {
                printf("[Size %.4d] : ", bytes_to_read);
                
                if (skip_flag == 1)
                {
                    printf("\n");
                }
                
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
            if(uOptFlag.flags.infile != 1)
            {
                printf("No input file enter.\n");    
                break;
            }
            else
            {
                bytes_to_read = 0;
                trustmReadDER(read_data_buffer, &bytes_to_read, inFile);
                if (bytes_to_read <= 0)
                {
                    printf("Read file: %s error!!!", inFile);
                }
            }
            
            printf("Offset: %d\n", offset);
            printf("Input data : \n");
            trustmHexDump(read_data_buffer,bytes_to_read);            

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_write_data(me_util,
                                                    optiga_oid,
                                                    mode,
                                                    offset,
                                                    read_data_buffer, 
                                                    bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                break;
            }

            while (OPTIGA_LIB_BUSY == optiga_lib_status) 
            {
                //Wait until the optiga_util_read_metadata operation is completed
            }

            if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
            {
                //Reading metadata data object failed.
                break;
            }
            if (return_status != OPTIGA_LIB_SUCCESS)
            {
                printf("Error!!! [0x%.8X]\n",return_status);
            }
            else
            {
                printf("Write Success.\n");
            }                
        }
    } while(0);
    printf("========================================================\n");    
    
    trustm_Close();
    return 0;
}
