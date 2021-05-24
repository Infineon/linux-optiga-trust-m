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
#include <string.h>
#include <openssl/engine.h>

#include "trustm_engine_common.h"
#include "trustm_helper.h"

#ifdef WORKAROUND
    extern void pal_os_event_disarm(void);
    extern void pal_os_event_arm(void);
#endif

static uint8_t dummy_public_key_2048[] = {
    0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
    0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,
    0x00,0xD8,0xFD,0xEA,0x6C,0xA2,0xF7,0x21,0xA1,0x7F,0x85,0xBF,0xB7,0x90,0x6F,0x8C,
    0x7F,0xF0,0x6B,0x65,0xDF,0x53,0x40,0x7A,0x87,0x14,0x2A,0x9A,0x55,0xBB,0xE7,0x8A,
    0x50,0xCA,0xB4,0xD5,0x0B,0x41,0xBA,0xDC,0x60,0xDE,0x2E,0x5B,0xDE,0x69,0xF3,0xE4,
    0x29,0x96,0x51,0x07,0xAB,0x38,0x3A,0xA3,0x33,0x8B,0xC3,0xFB,0xB1,0x88,0xA6,0x03,
    0x3B,0x21,0xAC,0x0A,0x31,0x05,0xFD,0xE0,0xCD,0x0F,0x40,0x0E,0xA7,0x37,0x1E,0x32,
    0x78,0x9D,0xB9,0x9B,0x38,0xAF,0x12,0x25,0x88,0x01,0xDB,0x3B,0x9C,0xE9,0x84,0x16,
    0x6F,0x1D,0x19,0x02,0x66,0xDD,0x96,0xC0,0xF9,0x64,0x04,0xAB,0x39,0x32,0xFC,0x08,
    0x90,0x82,0x2C,0xD6,0x66,0x8F,0x89,0x8C,0x7D,0xF1,0x3F,0x51,0x20,0xCA,0x36,0x72,
    0x29,0xA5,0xA8,0x8D,0xEB,0xD9,0x45,0x54,0xCD,0x5C,0x7F,0x4D,0x7A,0xC0,0x17,0xD1,
    0xB5,0xDA,0x42,0xB7,0x37,0x27,0xF7,0x29,0xBF,0x5D,0xD3,0xAB,0x57,0x90,0x0A,0xDC,
    0x2A,0x1D,0x97,0x5A,0x13,0x2F,0x77,0x77,0x38,0x6B,0x75,0x6A,0x2B,0x98,0x0B,0xD9,
    0x74,0xDB,0x54,0xD8,0xD4,0xAB,0xB4,0xEF,0xE1,0x9E,0x81,0xAC,0x3C,0x1E,0x84,0x63,
    0xBD,0xD9,0xC7,0xFC,0x6D,0xFB,0x91,0x70,0xF0,0x1D,0xBA,0xB1,0x1E,0x88,0x5A,0xDA,
    0xD9,0xAB,0x58,0xDE,0x13,0x47,0xC2,0xD3,0x58,0xC8,0x42,0x4D,0x53,0xCF,0x24,0x86,
    0xE4,0x60,0x11,0x8C,0x66,0x57,0xD1,0x3C,0xF4,0xFA,0xE7,0x5D,0xE2,0x2C,0x05,0x21,
    0x01,0x53,0x3D,0x8E,0x94,0xC1,0x36,0xB7,0xF6,0xAA,0x74,0xFC,0xC7,0x52,0xD0,0xCF,
    0x27,0x02,0x03,0x01,0x00,0x01
};


static uint8_t dummy_public_key_1024[] = {
    0x30,0x81,0x9F,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,
    0x05,0x00,0x03,0x81,0x8D,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xE1,0x15,0xA1,
    0x92,0x09,0x6F,0xFA,0xAE,0x75,0x6C,0xA1,0x34,0x1B,0xE1,0xB7,0x4C,0x47,0xFC,0xC1,
    0x72,0x25,0x01,0x8E,0x05,0xFD,0xB2,0xA9,0x37,0xD4,0xA3,0x72,0xEE,0x2A,0x9C,0xA4,
    0x5A,0xF4,0xBE,0x3D,0x06,0x75,0x21,0xEA,0x35,0x6D,0x73,0x83,0x7F,0x6F,0xE8,0x4C,
    0x9F,0x59,0x2E,0x1D,0xA8,0x7A,0xA0,0xD7,0x2C,0x91,0xBF,0x9D,0xE1,0x10,0x3A,0x90,
    0x85,0x7F,0xF9,0x12,0x86,0x96,0x47,0xC1,0xE9,0x11,0x85,0xC2,0x54,0xF6,0xFE,0xDB,
    0xDE,0xA1,0x04,0x65,0x66,0x54,0x7F,0x2F,0xB4,0x37,0x6E,0x52,0x87,0x9F,0x65,0xB2,
    0xA9,0xE0,0xE0,0xC0,0x69,0x76,0x51,0xB0,0x87,0x6B,0xF9,0x09,0xCC,0x70,0xA4,0x57,
    0x2C,0x7D,0x29,0x0C,0x87,0x34,0x2C,0x45,0xF8,0x4B,0xDF,0x48,0x89,0x02,0x03,0x01,
    0x00,0x01
};


const RSA_METHOD *default_rsa = NULL;
RSA_METHOD *rsa_methods = NULL;


static EVP_PKEY *trustm_rsa_generatekey(void)
{
    EVP_PKEY    *key         = NULL;

    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;

    uint8_t public_key [1024];
    uint16_t public_key_length = sizeof(public_key);
    uint16_t i, j;
    uint8_t *data;

    uint8_t rsaheader2048[] = {0x30,0x82,0x01,0x22,
                0x30,0x0d,
                0x06,0x09,
                0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00};

    uint8_t rsaheader1024[] = {0x30,0x81,0x9F,
                0x30,0x0D,
                0x06,0x09,
                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00};

    TRUSTM_ENGINE_DBGFN(">");

    TRUSTM_ENGINE_APP_OPEN_RET(key,NULL);
    do
    {
        if (trustm_ctx.rsa_key_type == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(rsaheader2048);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = rsaheader2048[i];
            }
        }
        else
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(rsaheader1024);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = rsaheader1024[i];
            }
        }

            optiga_lib_status = OPTIGA_LIB_BUSY;
            optiga_key_id = trustm_ctx.key_oid;
            return_status = optiga_crypt_rsa_generate_keypair(me_crypt,
                                                              trustm_ctx.rsa_key_type,
                                                              trustm_ctx.rsa_key_usage,
                                                              FALSE,
                                                              &optiga_key_id,
                                                              (public_key+i),
                                                              &public_key_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        printf("Please wait generating RSA key .......\n");
        trustmEngine_WaitForCompletion(MAX_RSA_KEY_GEN_TIME);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        data = public_key;

        if ((trustm_ctx.rsa_flag & TRUSTM_ENGINE_FLAG_SAVEPUBKEY) == TRUSTM_ENGINE_FLAG_SAVEPUBKEY)
        {
            TRUSTM_ENGINE_DBGFN("Save Pubkey to : 0x%.4X",(trustm_ctx.key_oid) + 0x10E4);

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_write_data(me_util,
                                (trustm_ctx.key_oid)+0x10E4,
                                OPTIGA_UTIL_ERASE_AND_WRITE,
                                0,
                                public_key,
                                public_key_length+i);
            if (OPTIGA_LIB_SUCCESS != return_status)
            break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
            break;
            else
            TRUSTM_ENGINE_DBGFN("Write Success \n");
        }

        trustm_ctx.pubkeylen = public_key_length+i;
        for(j=0;j<trustm_ctx.pubkeylen;j++)
        {
            trustm_ctx.pubkey[j] = *(data+j);
        }

        key = d2i_PUBKEY(NULL,(const unsigned char **)&data,public_key_length+i);
    } while (FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    
    
    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return key;
}

/*****************************************************************
 * trustm_rsa_loadkey
 *****************************************************************/
EVP_PKEY *trustm_rsa_loadkey(void)
{
    EVP_PKEY    *key = NULL;
    uint8_t *data;
    uint32_t len;

    TRUSTM_ENGINE_DBGFN(">");
    do
    {
        // New key request
        if ((trustm_ctx.rsa_flag & TRUSTM_ENGINE_FLAG_NEW) == TRUSTM_ENGINE_FLAG_NEW)
            key = trustm_rsa_generatekey();
        else // Load Pubkey
        {
            TRUSTM_ENGINE_DBGFN("no new key request\n");
            if (trustm_ctx.pubkeylen != 0)
            {
                data = &trustm_ctx.pubkey[0];
                len = trustm_ctx.pubkeylen;
                key = d2i_PUBKEY(NULL,(const unsigned char **)&data, len);
            }
            else
            {
                TRUSTM_ENGINE_DBGFN("No plubic Key found, Register Private Key only");
                //load dummy public key
                if(trustm_ctx.rsa_key_type == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
                {
                    data = dummy_public_key_2048;
                    len = sizeof(dummy_public_key_2048);
                }
                else
                {
                    data = dummy_public_key_1024;
                    len = sizeof(dummy_public_key_1024);
                }
                key = d2i_PUBKEY(NULL,(const unsigned char **)&data,len);
                trustm_ctx.pubkeylen = 0;
            }
        }
    } while (FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return key;
}

/** Encrypt data using priv trustM key
 *
 * @param flen Length of the from buffer.
 * @param from The data to be signed.
 * @param to The buffer to write the signature to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned signature
 */
static int trustmEngine_rsa_priv_enc(int flen,
                const unsigned char *from,
                unsigned char *to,
                RSA *rsa,
                int padding)
{
    int ret = TRUSTM_ENGINE_FAIL;
    optiga_lib_status_t return_status;
    uint16_t templen = 500;

    TRUSTM_ENGINE_DBGFN(">");

    TRUSTM_ENGINE_DBGFN("flen : %d",flen);
    TRUSTM_ENGINE_DBGFN("padding : %d", padding);
    TRUSTM_ENGINE_DBGFN("oid : 0x%X\n",trustm_ctx.key_oid);
    trustmHexDump((uint8_t *)from,flen);
    
    TRUSTM_ENGINE_APP_OPEN_RET(ret,TRUSTM_ENGINE_FAIL);
    do
    {
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_rsa_sign(me_crypt,
                              trustm_ctx.rsa_key_sig_scheme,
                              (uint8_t *)from,
                              flen,
                              trustm_ctx.key_oid,
                              to,
                              &templen,
                              0x0000);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        TRUSTM_ENGINE_DBGFN("to len : %d",templen);
        ret = templen;
    }while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    
    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

/** Decrypt data using priv trustM key
 * @param flen Length of the from buffer.
 * @param from The data to be decrypted.
 * @param to The buffer to write the plaintext to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned plaintext
 */
static int trustmEngine_rsa_priv_dec(int flen,
                const unsigned char *from,
                unsigned char *to,
                RSA * rsa,
                int padding)
{
    int ret = TRUSTM_ENGINE_FAIL;

    optiga_lib_status_t return_status;
    optiga_rsa_encryption_scheme_t encryption_scheme;
    uint8_t decrypted_message[2048];
    uint16_t decrypted_message_length = sizeof(decrypted_message);

    TRUSTM_ENGINE_DBGFN(">");
    //TRUSTM_ENGINE_DBGFN("From len : %d",flen);
    //trustmHexDump((uint8_t *)from,flen);
    
    TRUSTM_ENGINE_APP_OPEN_RET(ret,TRUSTM_ENGINE_FAIL);
    do
    {
        optiga_lib_status = OPTIGA_LIB_BUSY;
        encryption_scheme = OPTIGA_RSAES_PKCS1_V15;

        return_status = optiga_crypt_rsa_decrypt_and_export(me_crypt,
                                                            encryption_scheme,
                                                            from,
                                                            flen,
                                                            NULL,
                                                            0,
                                                            trustm_ctx.key_oid,
                                                            decrypted_message,
                                                            &decrypted_message_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        memcpy(to,decrypted_message,decrypted_message_length);
            printf("length : %d\n",decrypted_message_length);
            trustmHexDump(to,decrypted_message_length);
        ret = decrypted_message_length;

    } while (FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    

    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

/** Encrypt data using pub trustM key
 *
 * @param flen Length of the from buffer.
 * @param from The data to be signed.
 * @param to The buffer to write the signature to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned signature
 */
static int trustmEngine_rsa_pub_enc(int flen,
                const unsigned char *from,
                unsigned char *to,
                RSA * rsa,
                int padding)
{
    int ret = TRUSTM_ENGINE_FAIL;

    optiga_lib_status_t return_status;
    optiga_rsa_encryption_scheme_t encryption_scheme;
    uint8_t encrypted_message[2048];
    uint16_t encrypted_message_length = sizeof(encrypted_message);
    public_key_from_host_t public_key_from_host;

    TRUSTM_ENGINE_DBGFN(">");
    //TRUSTM_ENGINE_DBGFN("From len : %d",flen);
    //trustmHexDump((uint8_t *)from,flen);
    
    TRUSTM_ENGINE_APP_OPEN_RET(ret,TRUSTM_ENGINE_FAIL);
    do
    {
        optiga_lib_status = OPTIGA_LIB_BUSY;

        encryption_scheme = OPTIGA_RSAES_PKCS1_V15;

        public_key_from_host.public_key = (uint8_t *)(trustm_ctx.pubkey+trustm_ctx.pubkeyHeaderLen);
        public_key_from_host.length = (trustm_ctx.pubkeylen)-(trustm_ctx.pubkeyHeaderLen);

        if (trustm_ctx.rsa_key_type == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
            public_key_from_host.key_type = (uint8_t)OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
        else
            public_key_from_host.key_type = (uint8_t)OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;

        //printf("Pubkey:\n");
        //trustmHexDump(public_key_from_host.public_key, public_key_from_host.length);

        return_status = optiga_crypt_rsa_encrypt_message(me_crypt,
                                                            encryption_scheme,
                                                            from,
                                                            flen,
                                                            NULL,
                                                            0,
                                                            OPTIGA_CRYPT_HOST_DATA,
                                                            &public_key_from_host,
                                                            encrypted_message,
                                                            &encrypted_message_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        memcpy(to,encrypted_message,encrypted_message_length);
            //printf("length : %d\n",encrypted_message_length);
            //trustmHexDump(to,encrypted_message_length);
        ret = encrypted_message_length;

    } while (FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    
    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

/** Decrypt data using pub trustM key
 *
 * @param flen Length of the from buffer.
 * @param from The data to be signed.
 * @param to The buffer to write the signature to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned signature
 */
int trustmEngine_rsa_pub_dec(int flen,
                const unsigned char *from,
                unsigned char *to,
                RSA * rsa,
                int padding)
{
    int ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");

    do
    {
        TRUSTM_ENGINE_MSGFN("Function Not supported.");
        //Implement code here;
        //ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

static int trustmEngine_rsa_sign(int type,
                const unsigned char *m,
                unsigned int m_length,
                unsigned char *sigret,
                unsigned int *siglen,
                const RSA *rsa)
{
    int ret = TRUSTM_ENGINE_FAIL;
    optiga_lib_status_t return_status;
    uint16_t key_oid;
    uint16_t templen = 500;

    TRUSTM_ENGINE_DBGFN(">");

    TRUSTM_ENGINE_DBGFN("type : %d",type);
    TRUSTM_ENGINE_DBGFN("m_length : %d", m_length);
    //trustmHexDump((uint8_t *)m,m_length);


    TRUSTM_ENGINE_APP_OPEN_RET(ret,TRUSTM_ENGINE_FAIL);
    do
    {
        key_oid = trustm_ctx.key_oid;
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_rsa_sign(me_crypt,
                              trustm_ctx.rsa_key_sig_scheme,
                              (uint8_t *)m,
                              m_length,
                              key_oid,
                              sigret,
                              &templen,
                              0x0000);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        *siglen = templen;
        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    

    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

int trustmEngine_rsa_verify(int dtype,
                const unsigned char *m,
                unsigned int m_length,
                const unsigned char *sigbuf,
                unsigned int siglen,
                const RSA *rsa)
{
    int ret = TRUSTM_ENGINE_FAIL;
    optiga_lib_status_t return_status;
    public_key_from_host_t public_key_details;

    //uint8_t public_key[512];
    //uint16_t i;
    //uint16_t key_oid;
    //uint16_t templen = 500;

    TRUSTM_ENGINE_DBGFN(">");

    //TRUSTM_ENGINE_DBGFN("type : %d",dtype);
    //TRUSTM_ENGINE_DBGFN("m_length : %d", m_length);
    //trustmHexDump((uint8_t *)m,m_length);
    //TRUSTM_ENGINE_DBGFN("siglen : %d", siglen);
    //trustmHexDump((uint8_t *)sigbuf,siglen);

    //trustmHexDump(trustm_ctx.pubkey,trustm_ctx.pubkeylen);
    
    TRUSTM_ENGINE_APP_OPEN_RET(ret,TRUSTM_ENGINE_FAIL);
    do
    {
        if (trustm_ctx.pubkeylen == 0)
        {
             TRUSTM_ENGINE_ERRFN("Error No Public loaded!!!");
             break;
        }

        public_key_details.public_key = (uint8_t *)(trustm_ctx.pubkey+trustm_ctx.pubkeyHeaderLen);
        public_key_details.length = (trustm_ctx.pubkeylen)-(trustm_ctx.pubkeyHeaderLen);

        if (trustm_ctx.rsa_key_type == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
            public_key_details.key_type = (uint8_t)OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
        else
            public_key_details.key_type = (uint8_t)OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_rsa_verify (me_crypt,
                             trustm_ctx.rsa_key_sig_scheme,
                             (uint8_t *)m,
                             m_length,
                             sigbuf,
                             siglen,
                             OPTIGA_CRYPT_HOST_DATA,
                             &public_key_details,
                             0x0000);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;

        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    

    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
    trustmPrintErrorCode(return_status);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

static int trustmEngine_rsa_keygen(RSA *rsa,
                int bits,
                BIGNUM *e,
                BN_GENCB *cb)
{
    int ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");
    TRUSTM_ENGINE_DBG("bits: %d", bits);

    do
    {
        TRUSTM_ENGINE_MSGFN("Function Not supported.");

        //Implement code here;
        //ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

int trustmEngine_rsa_init(RSA *rsa)
{
    int ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");
    do
    {
        //Do not do anything here is it is call by other
        //RSA method
        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

static int trustmEngine_rsa_finish(RSA *rsa)
{
    int ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");
    do
    {
        //Implement code here;
        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}


/** Initialize the trusttm rsa
 *
 * @param e The engine context.
 */
uint16_t trustmEngine_init_rsa(ENGINE *e)
{
    uint16_t ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");
    do
    {
        default_rsa = RSA_PKCS1_OpenSSL();
        if (default_rsa == NULL)
            break;

        rsa_methods = RSA_meth_dup(default_rsa);
        RSA_meth_set1_name(rsa_methods, "TrustM RSA methods");

        RSA_meth_set_priv_enc(rsa_methods, trustmEngine_rsa_priv_enc);
        RSA_meth_set_priv_dec(rsa_methods, trustmEngine_rsa_priv_dec);

        RSA_meth_set_pub_enc(rsa_methods, trustmEngine_rsa_pub_enc);
        //RSA_meth_set_pub_dec(rsa_methods, trustmEngine_rsa_pub_dec);

        //RSA_meth_set_init(rsa_methods, trustmEngine_rsa_init);
        RSA_meth_set_finish(rsa_methods, trustmEngine_rsa_finish);

        RSA_meth_set_sign(rsa_methods, trustmEngine_rsa_sign);

        //RSA_meth_set_verify(rsa_methods, trustmEngine_rsa_verify);

        RSA_meth_set_keygen(rsa_methods, trustmEngine_rsa_keygen);

        ret = ENGINE_set_RSA(e, rsa_methods);

    }while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}
