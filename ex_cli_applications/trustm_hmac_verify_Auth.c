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
#include "optiga_util.h"
#include "optiga_crypt.h"

#include "pal_os_memory.h"
#include "pal_crypt.h"
#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
   
typedef struct _OPTFLAG {
        uint16_t        secretoid       : 1;
        uint16_t        secret          : 1;
        uint16_t        read            : 1;
        uint16_t        write           : 1;
        uint16_t        input           : 1;
        uint16_t        output          : 1;
        uint16_t        bypass          : 1;
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
    printf("\nHelp menu: trustm_hmac_verify_Auth <option> ...<option>\n");
    printf("option:- \n");
    printf("-I <OID>      : Input secret OID 0xNNNN \n");
    printf("                [default 0xF1D0]\n");
    printf("-s <filename> : Input user secret \n");
    printf("-r <OID>      : Read from target OID\n");
    printf("-w <OID>      : Write into target OID 0xNNNN \n");
    printf("-o <filename> : Output Data stored inside target OID\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}
static pal_status_t pal_crypt_hmac(pal_crypt_t* p_pal_crypt,
                                   uint16_t hmac_type,
                                   const uint8_t * secret_key,
                                   uint16_t secret_key_len,
                                   const uint8_t * input_data,
                                   uint32_t input_data_length,
                                   uint8_t * hmac)
{
    pal_status_t return_value = PAL_STATUS_FAILURE;

    const mbedtls_md_info_t * hmac_info;
    mbedtls_md_type_t digest_type;
    
    do
    {
#ifdef OPTIGA_LIB_DEBUG_NULL_CHECK
        if ((NULL == input_data) || (NULL == hmac))
        {
            break;
        }
#endif  //OPTIGA_LIB_DEBUG_NULL_CHECK

        digest_type = (((uint16_t)OPTIGA_HMAC_SHA_256 == hmac_type)? MBEDTLS_MD_SHA256: MBEDTLS_MD_SHA384);
        
        hmac_info = mbedtls_md_info_from_type(digest_type);

        if (0 != mbedtls_md_hmac(hmac_info, secret_key, secret_key_len, input_data, input_data_length, hmac))
        {
            break;
        }
        
        return_value = PAL_STATUS_SUCCESS;

    } while (FALSE);

    return return_value;
}

pal_status_t CalcHMAC(const uint8_t * secret_key,
                           uint16_t secret_key_len,
                           const uint8_t * input_data,
                           uint32_t input_data_length,
                           uint8_t * hmac)
{
    return(pal_crypt_hmac(NULL,
                          (uint16_t)OPTIGA_HMAC_SHA_256,
                          secret_key,
                          secret_key_len,
                          input_data,
                          input_data_length,
                          hmac));
}

pal_status_t pal_return_status;
uint16_t offset, bytes_to_read,bytes_to_read1;
uint8_t read_data_buffer[100];

/**
 * Optional data
 */
const uint8_t optional_data[] = 
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 
};

/**
 * random data
 */
uint8_t random_data[32] = {0x00};

/**
 * Arbitrary data
 */
const uint8_t arbitrary_data[] = 
{
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF 
};

/**
 * Input data
 */
uint8_t input_data_buffer[64] = {0x00};

/**
 * Generated hmac
 */
uint8_t hmac_buffer[32] = {0x00};

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    struct timeval start;
    struct timeval end;
    double time_taken;

    uint16_t secret_oid = 0xF1D0;// default secret OID;
    uint16_t target_oid = 0xF1D5;// default target OID;
    uint8_t hmac_type=0x20;// default HMAC_SHA256
    uint16_t offset, bytes_to_read,bytes_to_read1;
    uint8_t read_data_buffer[100];
    uint8_t user_secret[64];
    
    char *inFile = NULL;
    char *secFile = NULL;
    char *outFile = NULL;
    
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
        while (-1 != (option = getopt(argc, argv, "I:r:s:w:i:o:Xh")))
        {
            switch (option)
            {
                
                case 'I': // Secret OID
                        uOptFlag.flags.secretoid = 1;
                        secret_oid = trustmHexorDec(optarg);
                        printf("Input Secret OID: 0x%.4X\n",secret_oid);
                        if((secret_oid < 0xF1D0) || (secret_oid > 0xF1DB))
                        {
                                printf("Invalid Input Secret OID!!!\n");
                                exit(0);
                        }
                        break;
                case 's': // write secret from file
                        uOptFlag.flags.secret = 1;
                        secFile = optarg;
                        break;
                case 'r': // Read from Target OID
                        uOptFlag.flags.read = 1;
                        target_oid = trustmHexorDec(optarg);
                        printf("Target OID: 0x%.4X\n",target_oid);
                        break;
                case 'w': // Write into Target OID
                        uOptFlag.flags.write = 1;
                        target_oid = trustmHexorDec(optarg);
                        printf("Target OID: 0x%.4X\n",target_oid);
                        break;
                case 'i': // write data from file
                        uOptFlag.flags.input = 1;
                        inFile = optarg;
                        break;
                case 'o': // output the data stored inside target OID
                        uOptFlag.flags.output = 1;
                        outFile = optarg;
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
    if (return_status != OPTIGA_LIB_SUCCESS)
     {exit(1);}

    printf("========================================================\n");

    do
    {
        if(uOptFlag.flags.secretoid == 1)
        {
            if(uOptFlag.flags.secret != 1)
            {
                printf("Secret filename missing!!!\n");
                break;
            }
            printf("HMAC Type         : 0x%.4X \n",hmac_type);

            // Start performance timer
            gettimeofday(&start, NULL);

            if(uOptFlag.flags.bypass != 1)
            { 
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
            
            bytes_to_read1 = 0;
            trustmReadDER(user_secret, (uint32_t *)&bytes_to_read1, secFile);
            printf("Input secret : \n");
            trustmHexDump(user_secret,bytes_to_read1);              
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_generate_auth_code(me_crypt,
                                                            OPTIGA_RNG_TYPE_TRNG,
                                                            optional_data,
                                                            sizeof(optional_data),
                                                            random_data,
                                                            sizeof(random_data));

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
                

            /**
            * Calculate HMAC on host
            */
            pal_os_memcpy(input_data_buffer, optional_data, sizeof(optional_data));
            pal_os_memcpy(&input_data_buffer[sizeof(optional_data)], random_data, sizeof(random_data));
            pal_os_memcpy(&input_data_buffer[sizeof(optional_data) + sizeof(random_data)], arbitrary_data, sizeof(arbitrary_data));
            
            // Function name in line with SRM
            pal_return_status = CalcHMAC(user_secret,
                                    sizeof(user_secret),
                                    input_data_buffer,
                                    sizeof(input_data_buffer),
                                    hmac_buffer);

            if (PAL_STATUS_SUCCESS != pal_return_status)
            {
                // HMAC calculation on host failed
                return_status = pal_return_status;
                break;
            }        
            
            // Start performance timer
            gettimeofday(&start, NULL);

            /**
            * Perform HMAC verification using OPTIGA
            */
            // OPTIGA Comms Shielded connection settings to enable the protection
            if(uOptFlag.flags.bypass != 1)
            { 
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_hmac_verify(me_crypt,
                                                    hmac_type,
                                                    secret_oid,
                                                    input_data_buffer,
                                                    sizeof(input_data_buffer),
                                                    hmac_buffer,
                                                    sizeof(hmac_buffer));     
                                                 
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
            else
            {
                // stop performance timer.
                gettimeofday(&end, NULL);
                // Calculating total time taken by the program.
                time_taken = (end.tv_sec - start.tv_sec) * 1e6;
                time_taken = (time_taken + (end.tv_usec - start.tv_usec)) * 1e-6;
                printf("OPTIGA execution time: %0.4f sec.\n", time_taken);
                printf("HMAC verified successfully \n");
            }
            
            offset = 0x00;     
               
            if(uOptFlag.flags.write == 1)
            {   
                if(uOptFlag.flags.input != 1)
                {
                    printf("Input filename missing!!!\n");
                    break;
                }
                bytes_to_read = 0;
                trustmReadDER(read_data_buffer, (uint32_t *)&bytes_to_read, inFile);
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
                                                    target_oid,
                                                    OPTIGA_UTIL_ERASE_AND_WRITE,
                                                    0,
                                                    read_data_buffer,
                                                    bytes_to_read);

                if (OPTIGA_LIB_SUCCESS != return_status)
                {
                        break;
                }
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;
                else
                {
                    printf("Write new data into target OID successfully \n");
                }  
            } 
        
            if(uOptFlag.flags.read == 1)
            {
                if(uOptFlag.flags.output != 1)
                {
                    printf("Output filename missing!!!\n");
                    break;
                }
                printf("Output the data stored inside target OID. \n");
                printf("Output File Name : %s \n", outFile);
                bytes_to_read = sizeof(read_data_buffer);

                if(uOptFlag.flags.bypass != 1)
                {
                    // OPTIGA Comms Shielded connection settings to enable the protection
                    OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);
                }
                optiga_lib_status = OPTIGA_LIB_BUSY;        
                return_status = optiga_util_read_data(me_util,
                                                    target_oid,
                                                    offset,
                                                    read_data_buffer,
                                                    &bytes_to_read);
                if (OPTIGA_LIB_SUCCESS != return_status)
                {
                    break;
                }
                //Wait until the optiga_util_read_metadata operation is completed
                trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;
                else
                {
                    printf("Read data from target OID successfully \n");
                    printf("Data inside target OID :\n");
                    trustmHexDump(read_data_buffer,bytes_to_read);

                    return_status = trustmwriteTo(read_data_buffer,bytes_to_read,outFile);
                    if (return_status != OPTIGA_LIB_SUCCESS)
                    {
                        printf("Error when saving file!!!\n");
                    }
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
    return return_status;
}
