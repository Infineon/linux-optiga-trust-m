/**
* \copyright
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
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
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file main_raspberry_pi3_sample.c
*
* \brief   This sample demonstrates OPTIGA use cases.
*
* \ingroup grOptigaExamples
* @{
*/

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/common/optiga_lib_logger.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"

#include "trustm_helper.h"

void example_optiga_crypt_hash (void);
void example_optiga_crypt_ecc_generate_keypair(void);
void example_optiga_crypt_ecdsa_sign(void);
void example_optiga_crypt_ecdsa_verify(void);
void example_optiga_crypt_ecdh(void);
void example_optiga_crypt_random(void);
void example_optiga_crypt_tls_prf_sha256(void);
void example_optiga_util_read_data(void);
void example_optiga_util_write_data(void);
void example_optiga_crypt_rsa_generate_keypair(void);
void example_optiga_crypt_rsa_sign(void);
void example_optiga_crypt_rsa_verify(void);
void example_optiga_crypt_rsa_pre_master_secret(void);
void example_optiga_crypt_rsa_decrypt_and_export(void);
void example_optiga_crypt_rsa_decrypt_and_store(void);
void example_optiga_crypt_rsa_encrypt_message(void);
void example_optiga_crypt_rsa_encrypt_session(void);


/*******************************************************************
	main()
 *******************************************************************/
int32_t main(void)
{
    optiga_lib_status_t return_status;

    do
    {
        return_status = trustm_Open();
        if (return_status != OPTIGA_LIB_SUCCESS)
                break;

        printf("return_status: %x\n", return_status);
		
        //Example: Generate RSA pre master secret
        //example_optiga_crypt_rsa_pre_master_secret();

        // Example: Read data / metadata from a data object
        //example_optiga_util_read_data();

        // Example: Write data / metadata from a data object
        //example_optiga_util_write_data();

        //Example: Generate Random
        example_optiga_crypt_random();

        //Example: Generate Hash
        example_optiga_crypt_hash();

        //Example: Generate ECC Key pair
        example_optiga_crypt_ecc_generate_keypair();

        //Example: Sign the given digest
        example_optiga_crypt_ecdsa_sign();

        //Example: Verify the signature
        example_optiga_crypt_ecdsa_verify();

        //Example: Generate shared secret using ECDH
        example_optiga_crypt_ecdh();

        //Example: Derive the keys using TLS PRF SHA256
        example_optiga_crypt_tls_prf_sha256();
        
        //Example: Generate RSA Key pair
        example_optiga_crypt_rsa_generate_keypair();

        //Example: Sign the given digest using RSA signature scheme
        example_optiga_crypt_rsa_sign();
        
        //Example: Verify the rsa signature
        example_optiga_crypt_rsa_verify();
        
        //Example: Verify the rsa decrypt and export
        example_optiga_crypt_rsa_decrypt_and_export();
        
        //Example: Verify the rsa decrypt and store in session OID
        example_optiga_crypt_rsa_decrypt_and_store();
        
        // RSA Encryption of message
        example_optiga_crypt_rsa_encrypt_message();
        
        // RSA Encryption of session
        example_optiga_crypt_rsa_encrypt_session();
        
        /**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
         return_status = trustm_Close();
    }while(FALSE);

    return return_status;
}


