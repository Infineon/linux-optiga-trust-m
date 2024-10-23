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
    uint16_t    update      : 1;
    uint16_t    manifest    : 1;
    uint16_t    fragment    : 1;
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
    printf("\nHelp menu: trustm_protected_update_aeskey <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID>       : Target key OID: 0xE200 \n");
    printf("-f <filename>  : Fragment file\n");
    printf("-m <filename>  : Manifest file\n");
    printf("-X             : Bypass Shielded Communication \n");
    printf("-h             : Print this help \n");
}

const uint8_t target_key_oid_metadata[] = 
{
    0x20, 0x0C,
            0xC1, 0x02, 0x00, 0x00,
            0xD0, 0x03, 0x21, 0xE0, 0xE8,
            0xD3, 0x01, 0x00
};

typedef struct optiga_protected_update_manifest_fragment_configuration
{
    /// Manifest version.
    uint8_t manifest_version;
    /// Pointer to a buffer where manifest data is stored.
    const uint8_t * manifest_data;
    /// Manifest length
    uint16_t manifest_length;
    /// Pointer to a buffer where continue fragment data is stored.
    const uint8_t * continue_fragment_data;
    /// Continue fragment length
    uint16_t continue_fragment_length;
    /// Pointer to a buffer where final fragment data is stored.
    const uint8_t * final_fragment_data;
    /// Final fragment length
    uint16_t final_fragment_length;
}optiga_protected_update_manifest_fragment_configuration_t;

/**
 * \brief Specifies the structure for protected update data configuration
 */
typedef struct optiga_protected_update_data_configuration
{
    /// Target OID
    uint16_t target_key_oid;
    /// Target OID metadata
    const uint8_t * target_key_oid_metadata;
    /// Target OID metadata length
    uint16_t target_key_oid_metadata_length;
    /// Pointer to a buffer where continue fragment data is stored.
    const optiga_protected_update_manifest_fragment_configuration_t * data_config;
    /// Pointer to a protected update example string.
    const char * set_prot_example_string;    
}optiga_protected_update_data_configuration_t;
                                                          

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    uint16_t target_key_oid = 0xE200; 
    uint8_t manifest_aes_key[512]; 
    uint8_t aes_key_final_fragment_array[512];    
    uint16_t manifestLen = sizeof(manifest_aes_key);
    uint16_t fragmentLen = sizeof(aes_key_final_fragment_array);

    uint16_t data_config = 0;

    char *fragmentFile = NULL;
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
        while (-1 != (option = getopt(argc, argv, "k:m:f:Xh")))
        {
            switch (option)
            {
                case 'k': // target AES Key OID
                    uOptFlag.flags.update = 1;
                    target_key_oid = trustmHexorDec(optarg);
                    break;
                case 'f': // fragment
                    uOptFlag.flags.fragment = 1;
                    fragmentFile = optarg;
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

    do
    {
        if(uOptFlag.flags.fragment != 1)
        {
            printf("Fragment filename missing!!!\n");
            break;
        }

        if(uOptFlag.flags.manifest != 1)
        {
            printf("Manifest filename missing!!!\n");
            break;
        }
        
        manifestLen = trustmreadFrom(manifest_aes_key, (uint8_t *) manifestFile);
        if (manifestLen == 0)
        {
            printf("Error manifest reading file!!!\n");
            break;
        }       
        if (manifestLen > 512)
        {
            printf("Error: OPTIGA device Invalid Manifest!!!\n");
            break;
        }
        fragmentLen = trustmreadFrom(aes_key_final_fragment_array, (uint8_t *) fragmentFile);
        if (fragmentLen == 0)
        {
            printf("Error fragment reading file!!!\n");
            break;
        }
        if (fragmentLen > 512)
        {
            printf("Error: OPTIGA device Invalid fragment!!!\n");
            break;
        }
        printf("OID            : 0x%.4X\n",target_key_oid);
        printf("Manifest File Name : %s \n", manifestFile);
        printf("Manifest : \n");
        trustmHexDump(manifest_aes_key, manifestLen);
        printf("Fragment File Name     : %s \n", fragmentFile);
        printf("final fragment : \n");
        trustmHexDump(aes_key_final_fragment_array,fragmentLen);

 /**
 * AES key update manifest and fragment configuration
 */
    optiga_protected_update_manifest_fragment_configuration_t data_aes_key_configuration =
                                                                {
                                                                     0x01,
                                                                     manifest_aes_key,
                                                                     manifestLen,
                                                                     NULL,
                                                                     0,
                                                                     aes_key_final_fragment_array,
                                                                     fragmentLen
                                                                };                                                                                                                    
    const optiga_protected_update_data_configuration_t  optiga_protected_update_data_set[] =
    {
        {
            0xE200,
            target_key_oid_metadata,
            sizeof(target_key_oid_metadata),
            &data_aes_key_configuration, 
            "Protected Update - AES Key"
        },
    };
        
     for (data_config = 0; 
            data_config < \
            sizeof(optiga_protected_update_data_set)/sizeof(optiga_protected_update_data_configuration_t); data_config++)
       {

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_protected_update_start(me_util,
                                                               optiga_protected_update_data_set[data_config].data_config->manifest_version,
                                                               optiga_protected_update_data_set[data_config].data_config->manifest_data,
                                                               optiga_protected_update_data_set[data_config].data_config->manifest_length);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;

            if (NULL != optiga_protected_update_data_set[data_config].data_config->continue_fragment_data)
            {

                if(uOptFlag.flags.bypass != 1)
                {
                    // OPTIGA Comms Shielded connection settings to enable the protection
                    OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
                }
                
                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_util_protected_update_continue(me_util,
                                                                      optiga_protected_update_data_set[data_config].data_config->continue_fragment_data,
                                                                      optiga_protected_update_data_set[data_config].data_config->continue_fragment_length);
                if (OPTIGA_LIB_SUCCESS != return_status)
                    break;
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;

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
                OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
            }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_protected_update_final(me_util,
                                                               optiga_protected_update_data_set[data_config].data_config->final_fragment_data,
                                                               optiga_protected_update_data_set[data_config].data_config->final_fragment_length);
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
                printf("AES Key protected update Successful.\n");
            }

            printf("\n");
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
