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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define MAX_FRAGMENT_SIZE       640
#define MAX_NUM_OF_FRAGMENTS    3

typedef struct _OPTFLAG {
    uint16_t    update      : 1;
    uint16_t    manifest        : 1;
    uint16_t    cont1fragment   : 1;
    uint16_t    cont2fragment   : 1;
    uint16_t    finalfragment   : 1;
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
    printf("\nHelp menu: trustm_protected_update_data <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID>       : Target OID \n");
    printf("-c <filename>  : Continue 1 Fragment file\n");
    printf("-d <filename>  : Continue 2 Fragment file\n");  
    printf("-f <filename>  : Final Fragment file\n");
    printf("-m <filename>  : Manifest file\n");
    printf("-X             : Bypass Shielded Communication \n");
    printf("-h             : Print this help \n");
}


const uint8_t target_oid_metadata_with_confidentiality[] = 
{
    0x20, 0x09,
          //0xC1, 0x02, 0x00, 0x00,
          0xD0, 0x07, 0x21, 0xE0, 0xE8, 0xFD, 0x20, 0xF1, 0xD4
};
                                                          

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    uint16_t target_oid = 0xE0E1; 
    uint8_t manifest_int_conf[512];  
    uint16_t manifestLen = sizeof(manifest_int_conf);

    uint8_t fragmentArray[MAX_NUM_OF_FRAGMENTS][MAX_FRAGMENT_SIZE];
    uint16_t fragmentLen[MAX_NUM_OF_FRAGMENTS];

    uint8_t numFragmentsInt;


    char *finalFragmentFile = NULL;
    char *cont1FragmentFile = NULL;
    char *cont2FragmentFile = NULL;
    char *manifestFile = NULL;


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
        // -f : final fragment
        // -c : continue 1 fragment
        // -d : continue 2 fragment
        while (-1 != (option = getopt(argc, argv, "k:f:c:d:m:X:h")))
        {
            switch (option)
            {
                case 'k': // target OID 
                    uOptFlag.flags.update = 1;
                    target_oid = trustmHexorDec(optarg);
                    break;
                case 'f': // final fragment
                    uOptFlag.flags.finalfragment = 1;
                    finalFragmentFile = optarg;
                    break;
                case 'c': // first continue fragment
                    uOptFlag.flags.cont1fragment = 1;
                    cont1FragmentFile = optarg;
                    break;
                case 'd': // (if applicable) continue 2 fragment
                    uOptFlag.flags.cont2fragment = 1;
                    cont2FragmentFile = optarg;
                    break;
                case 'm': // manifest
                    uOptFlag.flags.manifest = 1;
                    manifestFile = optarg;
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


    if (uOptFlag.flags.finalfragment != 1 || (uOptFlag.flags.finalfragment == 1 && finalFragmentFile == NULL)) 
    {
        printf("Please specify final fragment file\n");
        exit(1);
    }
    
    if (uOptFlag.flags.cont1fragment == 1 && cont1FragmentFile == NULL)
    {
        printf("Please specify continue 1 fragment file\n");
        exit(1);
    }
    
    if (uOptFlag.flags.cont2fragment == 1 && cont2FragmentFile == NULL) 
    {
        printf("Please specify continue 2 fragment file\n");
        exit(1);
    }
    
    if (uOptFlag.flags.cont2fragment == 1 && uOptFlag.flags.cont1fragment != 1)
    {
        printf("Missing continue 1 fragment file\n");
        exit(1);
    }

    if(uOptFlag.flags.manifest != 1)
    {
        printf("Manifest filename missing!!!\n");
        exit(1);
    }
        
    manifestLen = trustmreadFrom(manifest_int_conf, (uint8_t *) manifestFile);
    if (manifestLen == 0)
    {
        printf("Error manifest reading file!!!\n");
        exit(1);
    }       
    if (manifestLen > 512)
    {
        printf("Error: OPTIGA device Invalid Manifest!!!\n");
        exit(1);
    }   
    
    
    // print manifest file info
    printf("OID            : 0x%.4X\n",target_oid);
    printf("File Name : %s \n", manifestFile);
    printf("Manifest : \n");
    trustmHexDump(manifest_int_conf, manifestLen);
    
    
    // only 1 fragment case
    if (uOptFlag.flags.finalfragment == 1 && uOptFlag.flags.cont1fragment != 1 && uOptFlag.flags.cont2fragment != 1)  
    {
        numFragmentsInt = 1;
        
        fragmentLen[0] = trustmreadFrom(&fragmentArray[0][0], (uint8_t *) finalFragmentFile);
        
        if (fragmentLen[0] == 0)
        {
            printf("Error final fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[0] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid final fragment!!!\n");
            exit(1);
        }
        
        printf("File Name     : %s \n", finalFragmentFile);
        printf("Final fragment : \n");
        trustmHexDump(&fragmentArray[0][0],fragmentLen[0]);
    }
    
    // 2 fragments case
    else if (uOptFlag.flags.finalfragment == 1 && uOptFlag.flags.cont1fragment == 1 && uOptFlag.flags.cont2fragment != 1)
    {
        numFragmentsInt = 2;
        
        fragmentLen[0] = trustmreadFrom(&fragmentArray[0][0], (uint8_t *) cont1FragmentFile);
        
        if (fragmentLen[0] == 0)
        {
            printf("Error continue 1 fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[0] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid continue 1 fragment!!!\n");
            exit(1);
        }
        
        fragmentLen[1] = trustmreadFrom(&fragmentArray[1][0], (uint8_t *) finalFragmentFile);
        
        if (fragmentLen[1] == 0)
        {
            printf("Error final fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[1] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid final fragment!!!\n");
            exit(1);
        }
        
        printf("File Name     : %s \n", cont1FragmentFile);
        printf("Continue 1 fragment : \n");
        trustmHexDump(&fragmentArray[0][0],fragmentLen[0]);
        printf("File Name     : %s \n", finalFragmentFile);
        printf("Final fragment : \n");
        trustmHexDump(&fragmentArray[1][0],fragmentLen[1]);
    }
    
    // 3 fragments case
    else if (uOptFlag.flags.finalfragment == 1 && uOptFlag.flags.cont1fragment == 1 && uOptFlag.flags.cont2fragment == 1)
    {
        numFragmentsInt = 3;
        
        fragmentLen[0] = trustmreadFrom(&fragmentArray[0][0], (uint8_t *) cont1FragmentFile);
        
        if (fragmentLen[0] == 0)
        {
            printf("Error continue 1 fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[0] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid continue 1 fragment!!!\n");
            exit(1);
        }
        
        fragmentLen[1] = trustmreadFrom(&fragmentArray[1][0], (uint8_t *) cont2FragmentFile);
        
        if (fragmentLen[1] == 0)
        {
            printf("Error continue 2 fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[1] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid continue 2 fragment!!!\n");
            exit(1);
        }
        
        fragmentLen[2] = trustmreadFrom(&fragmentArray[2][0], (uint8_t *) finalFragmentFile);
        
        if (fragmentLen[2] == 0)
        {
            printf("Error final fragment reading file!!!\n");
            exit(1);
        }
        
        if (fragmentLen[2] > MAX_FRAGMENT_SIZE)
        {
            printf("Error: OPTIGA device Invalid final fragment!!!\n");
            exit(1);
        }
        
        printf("File Name     : %s \n", cont1FragmentFile);
        printf("Continue 1 fragment : \n");
        trustmHexDump(&fragmentArray[0][0],fragmentLen[0]);
        printf("File Name     : %s \n", cont2FragmentFile);
        printf("Continue 2 fragment : \n");
        trustmHexDump(&fragmentArray[1][0],fragmentLen[1]);
        printf("File Name     : %s \n", finalFragmentFile);
        printf("Final fragment : \n");
        trustmHexDump(&fragmentArray[2][0],fragmentLen[2]);
    }

    else 
    {
        printf("Invalid fragment file arrangement. Exiting...\n");
        exit(0);
    }

    do {
        if(uOptFlag.flags.bypass != 1)
        {
            // OPTIGA Comms Shielded connection settings to enable the protection
            OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
            OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_protected_update_start(me_util,
                                                            1,
                                                            manifest_int_conf,
                                                            manifestLen);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            trustmPrintErrorCode(return_status);
            exit(1);
        }
        //Wait until the optiga_util_read_metadata operation is completed
        trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            trustmPrintErrorCode(return_status);
            exit(1);
        }

        int fragmentCounter = 0;

        if (numFragmentsInt > 1) 
        {
            for (fragmentCounter = 0; fragmentCounter < numFragmentsInt - 1; fragmentCounter++) {
                if(uOptFlag.flags.bypass != 1)
                {
                // OPTIGA Comms Shielded connection settings to enable the protection
                    OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
                }

                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_util_protected_update_continue(me_util,
                                                                &fragmentArray[fragmentCounter][0],
                                                                fragmentLen[fragmentCounter]);
                if (OPTIGA_LIB_SUCCESS != return_status)
                {
                    trustmPrintErrorCode(return_status);
                    exit(1);
                }
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                {
                    trustmPrintErrorCode(return_status);
                    exit(1);
                }
            }
        }
        if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_protected_update_final(me_util,
                                                               &fragmentArray[fragmentCounter][0],
                                                               fragmentLen[fragmentCounter]);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
                printf("Data protected update Successful.\n");

            printf("\n");
            
    } while (FALSE);    

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return 0;
}
