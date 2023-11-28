/**
* MIT License
*
* Copyright (c) 2023 Infineon Technologies AG
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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#include "optiga/optiga_util.h"
#include "optiga/optiga_crypt.h"
#include "optiga/pal/pal_os_datastore.h"
#include "optiga/pal/pal_os_memory.h"
#include "optiga/pal/pal_crypt.h"
#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"

#include "trustm_helper.h"

typedef struct _OPTFLAG {   
    uint16_t    write       : 1;
    uint16_t    read        : 1;
    uint16_t    invalue     : 1;
    uint16_t    infile      : 1;
    uint16_t    outfile     : 1;
    uint16_t    offset      : 1;
    uint16_t    erase       : 1;
    uint16_t    pbs         : 1;
    uint16_t    pbsvalue    : 1;
    uint16_t    pbsfile     : 1;
    uint16_t    auth        : 1;
    uint16_t    authvalue   : 1;
    uint16_t    authfile    : 1;
    uint16_t    bypass      : 1;
    uint16_t    cert        : 1;
    uint16_t    dummy15     : 1;
}OPTFLAG;

union _uOptFlag {
    OPTFLAG    flags;
    uint16_t    all;
} uOptFlag;

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


static void _helpmenu(void)
{
    printf("\nHelp menu: trustm_update_with_PBS_Auto <option> ...<option>\n");
    printf("option:- \n");
    printf("-r <OID>      : Read from OID 0xNNNN \n");
    printf("-w <OID>      : Write to OID \n");
    printf("-i <filename> : Input file \n");
    printf("-I <value>    : Input byte value \n");
    printf("-c <filename> : Input certificate to file\n");
    printf("-o <filename> : Output file \n");
    printf("-p <filename> : Input file with PBS\n");
    printf("-P <value>    : Input byte value with PBS\n");
    printf("-a <filename> : Input file with Authorization Reference\n");
    printf("-A <value>    : Input byte value with Authorization Reference\n");
    printf("-e            : Erase and write \n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}



int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    pal_status_t pal_return_status;
    
    struct timeval start;
    struct timeval end;
    double time_taken;

    uint16_t offset =0;
    uint32_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t pbs_buffer[64];
    uint8_t auth_buffer[64];
    uint8_t mode = OPTIGA_UTIL_WRITE_ONLY;

    X509 *x509Cert;

    char  messagebuf[500];

    char *outFile = NULL;
    char *inFile = NULL;
    char *inValue = NULL;
    
    char *pbsFile = NULL;
    char *pbsInput = NULL;
    char *authFile = NULL;
    char *authInput = NULL;


    int option = 0;                    // Command line option.

    uint16_t secret_oid = 0xF1D0;// default secret OID;
    uint8_t hmac_type=0x20;// default HMAC_SHA256

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
        while (-1 != (option = getopt(argc, argv, "w:r:i:I:p:P:a:A:c:eXh")))
        {
            switch (option)
            {
                case 'w': // Write OID
                    uOptFlag.flags.write = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'r': // Read OID
                    uOptFlag.flags.read = 1;
                    optiga_oid = trustmHexorDec(optarg);
                    break;
                case 'i': // Input filename
                    uOptFlag.flags.infile = 1;
                    inFile = optarg;
                    break;
                case 'I': // Input value
                    uOptFlag.flags.invalue = 1;
                    inValue = optarg;
                    break;
                case 'p': // Input PBS filename
                    uOptFlag.flags.pbs = 1;
                    uOptFlag.flags.pbsfile = 1;
                    pbsFile = optarg;
                    break;
                case 'P': // Input PBS value
                    uOptFlag.flags.pbs = 1;
                    uOptFlag.flags.pbsvalue = 1;
                    pbsInput = optarg;
                    break;
                case 'a': // Input Auto filename
                    uOptFlag.flags.auth = 1;
                    uOptFlag.flags.authfile = 1;
                    authFile = optarg;
                    break;
                case 'A': // Input Auto value
                    uOptFlag.flags.auth = 1;
                    uOptFlag.flags.authvalue = 1;
                    authInput = optarg;
                    break;
                case 'e': // erase
                    uOptFlag.flags.erase = 1;
                    mode = OPTIGA_UTIL_ERASE_AND_WRITE;
                    break;
                case 'c': // erase
                    uOptFlag.flags.cert = 1;
                    inFile = optarg;
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

    trustmGetOIDName(optiga_oid, messagebuf);
    printf("========================================================\n");
    puts(messagebuf);

    do
    {

        if (uOptFlag.flags.pbs == 1)
        {   
            if (uOptFlag.flags.pbsfile == 1) 
            {
                bytes_to_read = 0;
                trustmReadDER(pbs_buffer, &bytes_to_read, pbsFile);
                if (bytes_to_read <= 0)
                {
                    printf("Read file: %s error!!!", pbsFile);
                }
            } 
            else 
            {
                bytes_to_read = 64;
                
                for (size_t count = 0; count < sizeof pbs_buffer/sizeof *pbs_buffer; count++) {
                    sscanf(pbsInput, "%2hhx", &pbs_buffer[count]);
                    pbsInput += 2;
                }
            }

            pal_return_status = pal_os_datastore_write(OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID,
                                pbs_buffer, 
                                sizeof(pbs_buffer));
            if (PAL_STATUS_SUCCESS != pal_return_status)
            {
                //Storing of Pre-shared secret on Host failed.
                return_status = pal_return_status;
                break;
            }
        } else {
            printf("No PBS given. Using default value.\n");
        }

        if (uOptFlag.flags.auth == 1)
        {   
            if (uOptFlag.flags.authfile == 1) 
            {
                bytes_to_read = 0;
                trustmReadDER(auth_buffer, &bytes_to_read, authFile);
                if (bytes_to_read <= 0)
                {
                    printf("Read file: %s error!!!", authFile);
                }
            } 
            else 
            {
                bytes_to_read = 64;
                
                for (size_t count = 0; count < sizeof auth_buffer/sizeof *auth_buffer; count++) {
                    sscanf(authInput, "%2hhx", &auth_buffer[count]);
                    authInput += 2;
                }
            }

            // if(uOptFlag.flags.bypass != 1)
            // {
            //     // OPTIGA Comms Shielded connection settings to enable the protection
            //     OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
            //     OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            // }
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
                printf("No Auth Code Generation!\n");
                break;
            }  
                

            /**
            * Calculate HMAC on host
            */
            pal_os_memcpy(input_data_buffer, optional_data, sizeof(optional_data));
            pal_os_memcpy(&input_data_buffer[sizeof(optional_data)], random_data, sizeof(random_data));
            pal_os_memcpy(&input_data_buffer[sizeof(optional_data) + sizeof(random_data)], arbitrary_data, sizeof(arbitrary_data));
            
            // Function name in line with SRM
            pal_return_status = CalcHMAC(auth_buffer,
                                    sizeof(auth_buffer),
                                    input_data_buffer,
                                    sizeof(input_data_buffer),
                                    hmac_buffer);

            if (PAL_STATUS_SUCCESS != pal_return_status)
            {
                // HMAC calculation on host failed
                printf("No PAL HMAC Calculation!\n");
                return_status = pal_return_status;
                break;

            }        
            
            /**
            * Perform HMAC verification using OPTIGA
            */

            // OPTIGA Comms Shielded connection settings to enable the protection
            OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
            OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
    
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
                printf("No OPTIGA HMAC Verification!\n");
                break;
            }
            // else
            // {
            //     printf("HMAC verified successfully \n");
            // }
        } else {
            printf("No Authorization Reference given. Will not clear the Authorization State\n");
        }

        if(uOptFlag.flags.read == 1)
        {

            // Start performance timer
            gettimeofday(&start, NULL);

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
            if((uOptFlag.flags.infile != 1) && (uOptFlag.flags.invalue != 1) && (uOptFlag.flags.cert != 1))
            {
                printf("Input filename or value missing!\n");
                break;
            }

            if ((uOptFlag.flags.infile == 1) && (uOptFlag.flags.cert == 1)) 
            {
                printf("Cannot have both input filename and input cert name!\n");
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
            else if (uOptFlag.flags.cert == 1)
            {
                uint16_t ret = trustmReadX509PEM(&x509Cert, inFile);
                if (ret == 0)
                {
                    uint8_t *pCert;
                    bytes_to_read = i2d_X509(x509Cert, &pCert);
                    pal_os_memcpy(read_data_buffer, pCert, bytes_to_read);
                }
                else
                {
                    printf("Read Cert %s Error!!!\n",inFile);
                }
            }
            else
            {
                    bytes_to_read = 0;
                    for (size_t count = 0; count < sizeof(inValue); count++) {
                    sscanf(inValue, "%2hhx", &read_data_buffer[count]);
                    inValue += 2;
                    bytes_to_read++;
                }
            }

            printf("Offset: %d\n", offset);
            printf("Input data : \n");
            trustmHexDump(read_data_buffer,bytes_to_read);

            // Start performance timer
            gettimeofday(&start, NULL);

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
                printf("Write Success.\n");
            }
        }

        // Reset authentication state
        if (uOptFlag.flags.auth == 1)
        {
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_clear_auto_state(me_crypt, secret_oid);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            if (return_status != OPTIGA_LIB_SUCCESS) 
                break;
        }
    } while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return return_status;
}
