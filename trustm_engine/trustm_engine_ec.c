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

unsigned char dummy_ec_public_key_256[] = 
{
    0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,
    0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,
    0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x01,0xA0,0x07,
    0x7B,0xB3,0x69,0xFD,0x88,0xD5,0x48,0xB7,0x98,0xBD,
    0x42,0xA2,0xF2,0x83,0xAD,0x19,0x31,0xDE,0x83,0x82,
    0xE8,0xA7,0xF7,0x6F,0xB0,0x01,0x95,0x35,0xE4,0xFD,
    0xBD,0x45,0x79,0x01,0xCC,0xAF,0x2F,0xF1,0x8C,0xBF,
    0x0E,0x18,0xE6,0x43,0x3D,0xB8,0x1D,0xFB,0xB1,0x04,
    0xAB,0x29,0x50,0x71,0x50,0x16,0x34,0x7A,0x04,0xF3,
    0x1F
};

unsigned char dummy_ec_public_key_384[] = 
{
    0x30,0x76,0x30,0x10,0x06,0x07,0x2A,0x86,0x48,0xCE,
    0x3D,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,0x22,
    0x03,0x62,0x00,0x04,0xF8,0xBF,0xC2,0xFA,0xDF,0xBD,
    0xC7,0x2D,0xA1,0x95,0x5C,0xCD,0xF3,0x4B,0x89,0x25,
    0x7F,0xC8,0x09,0x2D,0xD6,0xDA,0xE1,0x6C,0xE8,0x45,
    0xDD,0x8B,0x61,0x24,0x20,0xEE,0x64,0x9B,0xE0,0x4B,
    0xA1,0xD6,0x1A,0x80,0xC3,0xB1,0xCE,0x6F,0xB0,0xB9,
    0xC9,0x65,0x21,0x38,0x73,0xE8,0x50,0xBC,0xAB,0x9D,
    0xB2,0x21,0xCA,0xE9,0xBB,0x5A,0xD6,0x2C,0xB4,0xDC,
    0x2F,0x02,0xB2,0x57,0x52,0xD0,0x43,0xF5,0xB8,0xDD,
    0x6B,0x54,0x38,0xCA,0x95,0x46,0x15,0x10,0xEB,0x9E,
    0xE3,0xFE,0x89,0xB3,0x93,0x58,0x60,0xDC,0x0A,0xD5
};

unsigned char dummy_ec_public_key_521[] = 
{
    0x30,0x81,0x9B,0x30,0x10,0x06,0x07,0x2A,0x86,0x48,
    0xCE,0x3D,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,
    0x23,0x03,0x81,0x86,0x00,0x04,0x01,0xEA,0xFE,0xBC,
    0x27,0xA7,0x7C,0x3C,0xD6,0xE3,0x7C,0x0A,0x30,0x97,
    0x7D,0xCD,0x60,0x24,0xA4,0x17,0xC4,0x1C,0xEF,0x44,
    0x17,0x2C,0x5E,0x0E,0x3C,0xC8,0xE3,0x89,0x32,0x3F,
    0xB3,0x86,0x5B,0xCE,0x26,0x04,0xD4,0x8F,0xB6,0x56,
    0x7C,0x45,0x5B,0x13,0xA0,0x40,0x68,0x2E,0x2D,0xFD,
    0xA2,0x41,0xA6,0xEB,0x0F,0xB6,0x77,0x01,0x56,0xDC,
    0x59,0x75,0x00,0x02,0x05,0x4C,0x02,0xB7,0x52,0x59,
    0x91,0xD5,0x47,0x83,0xAF,0xC1,0x90,0x08,0x37,0x46,
    0x8E,0x92,0x3D,0x1A,0x6C,0x00,0x5F,0x15,0xB7,0x3D,
    0xFC,0x3B,0x64,0xA9,0x62,0x7F,0x5B,0xE3,0x9D,0xC2,
    0xEE,0x7D,0xF3,0x1A,0x14,0x7D,0xAE,0x95,0xAE,0x80,
    0x14,0x2F,0x63,0xC5,0xD0,0xE0,0xBB,0x69,0x1E,0xCC,
    0x93,0xD4,0xEE,0xB0,0x9A,0xBA,0x68,0xC2
};

unsigned char dummy_ec_public_key_BrainPool256[] = 
{
    0x30,0x5a,0x30,0x14,0x06,0x07,0x2a,0x86,0x48,0xce,
    0x3d,0x02,0x01,0x06,0x09,0x2b,0x24,0x03,0x03,0x02,
    0x08,0x01,0x01,0x07,0x03,0x42,0x00,0x04,0x4c,0xc4,
    0x72,0x5b,0x26,0x3e,0xbb,0x47,0x7d,0x4c,0x2a,0x80,
    0x7c,0x46,0x07,0x6d,0x0e,0x8c,0x40,0x21,0x95,0x0b,
    0xd6,0x47,0xf9,0x13,0x52,0xa5,0x7f,0xd4,0xb5,0x3f,
    0x6c,0x94,0x8f,0x53,0x2b,0xec,0x7b,0xa5,0x1e,0x2a,
    0x26,0x03,0x3a,0x49,0x23,0x80,0xc4,0x98,0xe5,0xe9,
    0xb5,0x5e,0xa9,0x5d,0x0a,0x51,0x45,0x71,0x30,0xff,
    0x17,0xb9
};

unsigned char dummy_ec_public_key_BrainPool384[] = 
{
    0x30,0x7a,0x30,0x14,0x06,0x07,0x2a,0x86,0x48,0xce,
    0x3d,0x02,0x01,0x06,0x09,0x2b,0x24,0x03,0x03,0x02,
    0x08,0x01,0x01,0x0b,0x03,0x62,0x00,0x04,0x16,0xd1,
    0xef,0xb3,0x1d,0xf2,0x81,0xe5,0x2e,0x42,0xb3,0x83,
    0xd3,0xf6,0xe9,0x7b,0xab,0xf3,0x37,0xd2,0x5b,0xbe,
    0x00,0x8e,0x6b,0x03,0x7c,0x86,0xc2,0x2b,0x6c,0xbc,
    0x70,0x0b,0x13,0x58,0x12,0x26,0x44,0x1b,0x7e,0xc3,
    0x27,0x0a,0x20,0xb7,0x02,0x17,0x58,0x73,0x7b,0x55,
    0xb9,0xdd,0x3a,0x7d,0x04,0xd9,0x90,0x22,0x1a,0x5d,
    0xb8,0x58,0xa1,0xa5,0x88,0xb8,0xcb,0xf4,0x04,0xdf,
    0x4f,0x82,0x72,0x91,0x92,0x65,0x4c,0xf6,0xfe,0x67,
    0x7c,0x82,0x6d,0xc9,0xe0,0x14,0x77,0xea,0xb2,0xb2,
    0x23,0x17,0xe0,0xf0
};

unsigned char dummy_ec_public_key_BrainPool512[] = 
{
    0x30,0x81,0x9b,0x30,0x14,0x06,0x07,0x2a,0x86,0x48,
    0xce,0x3d,0x02,0x01,0x06,0x09,0x2b,0x24,0x03,0x03,
    0x02,0x08,0x01,0x01,0x0d,0x03,0x81,0x82,0x00,0x04,
    0x3f,0x7b,0x6b,0xe0,0x58,0x46,0x0d,0xa1,0xee,0x71,
    0x82,0x18,0x96,0x59,0xd0,0x3e,0xc8,0x58,0x0b,0x9a,
    0x29,0x16,0x68,0x21,0xde,0x66,0x00,0xda,0xd4,0xf3,
    0x4b,0xd5,0x3a,0x2a,0x6c,0xcb,0x40,0x5d,0xe0,0xe7,
    0xf9,0x37,0xdd,0xba,0x01,0xaa,0x37,0xd0,0x1f,0x14,
    0xe9,0xd4,0x43,0x4b,0x14,0xbc,0x2c,0x52,0xb6,0x82,
    0xae,0xa8,0xcf,0x0a,0x99,0xfd,0x51,0xde,0x4a,0x61,
    0x43,0x93,0x5e,0xd4,0x53,0xea,0xed,0xad,0x0d,0xff,
    0x8e,0x58,0x27,0x7d,0x3e,0xfb,0x09,0x99,0x72,0x13,
    0xee,0x55,0xca,0x73,0x35,0x90,0x6a,0x53,0xeb,0xe9,
    0x10,0xa2,0x32,0xcd,0xf0,0x6c,0x2c,0x33,0x7d,0xa8,
    0x04,0x15,0x96,0x64,0x0e,0xc9,0x4b,0x62,0x8c,0xfd,
    0x43,0xea,0xb2,0xbc,0x75,0xef,0x04,0xea
};

EVP_PKEY *trustm_ec_generatekey(void)
{
    EVP_PKEY    *key         = NULL;

    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;

    uint8_t public_key [500];
    uint16_t public_key_length = sizeof(public_key);
    uint16_t i,j;
    uint8_t *data;

    uint8_t eccheader256[] = {0x30,0x59, // SEQUENCE
                                0x30,0x13, // SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x08, // OID:1.2.840.10045.3.1.7
                                0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
                
    uint8_t eccheader384[] = {0x30,0x76, // SEQUENCE
                                0x30,0x10, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x05, // OID:1.3.132.0.34
                                0x2B,0x81,0x04,0x00,0x22};
                                
    uint8_t eccheader521[] = {0x30,0x81,0x9B, // SEQUENCE
                                0x30,0x10, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x05, // OID:1.3.132.0.35
                                0x2B,0x81,0x04,0x00,0x23};  
                                
    uint8_t eccheaderBrainPool256[] = {0x30,0x5A, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.132.0.35
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07}; 
    uint8_t eccheaderBrainPool384[] = {0x30,0x7A, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.132.0.35
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B};   
    uint8_t eccheaderBrainPool512[] = {0x30,0x81,0x9B, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.13
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d};                                                                                    

    TRUSTM_ENGINE_DBGFN(">");
    
    TRUSTM_ENGINE_APP_OPEN_RET(key,NULL);
    do
    {
        if (trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_256)
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheader256);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheader256[i];
            }
        } 
        else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_384)   
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheader384);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheader384[i];
            }
        }
        else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_521)   
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheader521);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheader521[i];
            }
        }
        else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1)   
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheaderBrainPool256);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheaderBrainPool256[i];
            }
        }
        else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)    
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheaderBrainPool384);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheaderBrainPool384[i];
            }
        }
        else    
        {
            trustm_ctx.pubkeyHeaderLen = sizeof(eccheaderBrainPool512);
            for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
            {
            public_key[i] = eccheaderBrainPool512[i];
            }
        }

        optiga_key_id = trustm_ctx.key_oid;
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecc_generate_keypair(me_crypt,
                                  trustm_ctx.ec_key_curve,
                                  trustm_ctx.ec_key_usage,
                                  FALSE,
                                  &optiga_key_id,
                                  (public_key+i),
                                  &public_key_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;          
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            break;
        }
            //printf("length : %d\n",public_key_length+i);
            //trustmHexDump(public_key,public_key_length+i);
            //trustmWriteDER(public_key, public_key_length+i, "myTest.key");

        data = public_key;

        if ((trustm_ctx.ec_flag & TRUSTM_ENGINE_FLAG_SAVEPUBKEY) == TRUSTM_ENGINE_FLAG_SAVEPUBKEY)
        {
            if((trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)){
                TRUSTM_ENGINE_DBGFN("Save Pubkey to : 0x%.4X",(trustm_ctx.key_oid) + 0x10ED);}
            else{TRUSTM_ENGINE_DBGFN("Save Pubkey to : 0x%.4X",(trustm_ctx.key_oid) + 0x10E0);}

            // Save pubkey without header
            optiga_lib_status = OPTIGA_LIB_BUSY;
            if((trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)){
                return_status = optiga_util_write_data(me_util,
                                (trustm_ctx.key_oid)+0x10ED,
                                OPTIGA_UTIL_ERASE_AND_WRITE,
                                0,
                                public_key, 
                                public_key_length+i);}
            else{
                return_status = optiga_util_write_data(me_util,
                                (trustm_ctx.key_oid)+0x10E0,
                                OPTIGA_UTIL_ERASE_AND_WRITE,
                                0,
                                public_key, 
                                public_key_length+i);}
                                
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
    {
        TRUSTM_ENGINE_DBGFN("testpoint 1!!!!!!!!!!");
        key = NULL;
    }

    TRUSTM_ENGINE_DBGFN("<");   
    return key;
}

EVP_PKEY *trustm_ec_loadkeyE0E0(void)
{
    EVP_PKEY    *key = NULL;
    X509        *x509_cert   = NULL;
  
    uint16_t offset, bytes_to_read;
    uint8_t read_data_buffer[5000];
    const unsigned char *pCert;
    uint16_t certLen;
    uint8_t *data; 
    int j; 
    
    optiga_lib_status_t return_status;

    
    TRUSTM_ENGINE_APP_OPEN_RET(key,NULL);
    do
    {
        offset = 9;
        bytes_to_read = sizeof(read_data_buffer);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_read_data(me_util,
                                            0xE0E0,
                                            offset,
                                            read_data_buffer,
                                            (uint16_t *)&bytes_to_read);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;
        //Wait until the optiga_util_read_metadata operation is completed
        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;
        else
        {
            pCert = read_data_buffer;
            certLen = bytes_to_read;

        x509_cert = d2i_X509(NULL, &pCert, certLen);
        TRUSTM_ENGINE_DBGFN("Parsed X509 from raw cert");
  
        data = trustm_ctx.pubkey;
        key = X509_get_pubkey(x509_cert);
        trustm_ctx.pubkeylen = i2d_PUBKEY(key,&data);

        j=0;    
        if((trustm_ctx.pubkey[1] & 0x80) == 0x00)
        {
        j = trustm_ctx.pubkey[3] + 4;
        }
        else
        {
        j = (trustm_ctx.pubkey[1] & 0x7f);
        j = trustm_ctx.pubkey[j+3] + j + 4; 
        }
        trustm_ctx.pubkeyHeaderLen = j;
        
        //trustmHexDump(trustm_ctx.pubkey,trustm_ctx.pubkeylen);
        
        if (key == NULL)
        {
        TRUSTM_ENGINE_ERRFN("failed to extract public key from X509 certificate");
        break;
        }
        TRUSTM_ENGINE_DBGFN("Extracted public key from cert");
      }

    } while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    
    
    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
        key = NULL;

    TRUSTM_ENGINE_DBGFN("<");   
    return key;        
}

EVP_PKEY *trustm_ec_loadkey(void)
{
    EVP_PKEY    *key = NULL;
    uint8_t *data;
    uint32_t len;


    TRUSTM_ENGINE_DBGFN(">");
    do
    {
        // New key request
        if ((trustm_ctx.ec_flag & TRUSTM_ENGINE_FLAG_NEW) == TRUSTM_ENGINE_FLAG_NEW)
            key = trustm_ec_generatekey();
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
            TRUSTM_ENGINE_DBGFN("No public Key found, Register Private Key only");
            //load dummy public key
            if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_256)
            {
                data = dummy_ec_public_key_256;
                len = sizeof(dummy_ec_public_key_256);
            }
            else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_384)
            {
                data = dummy_ec_public_key_384;
                len = sizeof(dummy_ec_public_key_384);
            }
            else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_521)
            {
                data = dummy_ec_public_key_521;
                len = sizeof(dummy_ec_public_key_521);
            }
            else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1)
            {
                data = dummy_ec_public_key_BrainPool256;
                len = sizeof(dummy_ec_public_key_BrainPool256);
            }
            else if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)
            {
                data = dummy_ec_public_key_BrainPool384;
                len = sizeof(dummy_ec_public_key_BrainPool384);
            }
            else
            {
                data = dummy_ec_public_key_BrainPool512;
                len = sizeof(dummy_ec_public_key_BrainPool512);
            }
            key = d2i_PUBKEY(NULL,(const unsigned char **)&data,len);
            trustm_ctx.pubkeylen = 0;
            }
        }
    } while (FALSE);
      
    TRUSTM_ENGINE_DBGFN("<");   
    return key;      
}

static ECDSA_SIG* trustm_ecdsa_sign(
  const unsigned char  *dgst,
  int                   dgstlen,
  const BIGNUM         *in_kinv,
  const BIGNUM         *in_r,
  EC_KEY               *eckey
)
{
    ECDSA_SIG  *ecdsa_sig = NULL;

    uint8_t     sig[500];
    uint16_t    sig_len = 500;

    optiga_lib_status_t return_status;

    TRUSTM_ENGINE_DBGFN(">");
    TRUSTM_ENGINE_DBGFN("oid : 0x%.4x",trustm_ctx.key_oid);
    TRUSTM_ENGINE_DBGFN("dgst len : %d",dgstlen);

    // TODO/HACK:
    if (dgstlen != 32)
    {
    dgstlen = 32;
    TRUSTM_ENGINE_DBGFN("APPLIED digest length hack");
    }

       
    TRUSTM_ENGINE_APP_OPEN_RET(ecdsa_sig,NULL);
    do 
    {  
        optiga_lib_status = OPTIGA_LIB_BUSY;
        if((trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1))
        {
            return_status = optiga_crypt_ecdsa_sign(me_crypt,
                                dgst,
                                dgstlen,
                                trustm_ctx.key_oid,
                                (sig+3),
                                &sig_len);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;          
            //Wait until the optiga_util_read_metadata operation is completed
            trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                TRUSTM_ENGINE_DBGFN("Signature received : sig+3=%x, sig_len=0x%x=%d",
                (unsigned int) sig+3,
                sig_len, sig_len);

                sig[0] = 0x30;
                sig[1] = 0x81;
                sig[2] = sig_len;
                TRUSTM_ENGINE_DBGFN("ecc curve: 0x%.4x",trustm_ctx.ec_key_curve);
                trustmHexDump(sig,sig_len+3);            
                const unsigned char *p = sig;
                ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len+3);
            }
        }
        else
        {
            return_status = optiga_crypt_ecdsa_sign(me_crypt,
                            dgst,
                            dgstlen,
                            trustm_ctx.key_oid,
                            (sig+2),
                            &sig_len);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;          
            //Wait until the optiga_util_read_metadata operation is completed
            trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                TRUSTM_ENGINE_DBGFN("Signature received : sig+2=%x, sig_len=0x%x=%d",
                (unsigned int) sig+2,
                sig_len, sig_len);

                sig[0] = 0x30;
                sig[1] = sig_len;
                const unsigned char *p = sig;
                ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len+2);
            }
        }
    }while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;
    

    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);    
    
    TRUSTM_ENGINE_DBGFN("<");
    //return ret;
    return ecdsa_sig;
} 

/*
 * Initializes the global engine context.
 * Return 1 on success, otherwise 0.
 */
uint16_t trustmEngine_init_ec(ENGINE *e)
{
  uint16_t ret = TRUSTM_ENGINE_FAIL;
  int (*orig_sign) (int, const unsigned char *, int, unsigned char *,
                    unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *)
        = NULL;

  // Verify method
  int (*orig_verify)(int type,const unsigned char *dgst,int dgst_len,const unsigned char *sigbuf,
            int sig_len,EC_KEY *eckey) = NULL;
  int (*orig_verify_sig)(const unsigned char *dgst,int dgst_len,const ECDSA_SIG *sig,
            EC_KEY *eckey) = NULL;

  TRUSTM_ENGINE_DBGFN(">");

  do {
    trustm_ctx.default_ec = EC_KEY_OpenSSL();
    if (trustm_ctx.default_ec == NULL)
      break;

    trustm_ctx.ec_key_method = EC_KEY_METHOD_new(trustm_ctx.default_ec);
    if (    trustm_ctx.ec_key_method == NULL)
      break;

    EC_KEY_METHOD_get_sign(trustm_ctx.ec_key_method, &orig_sign, NULL, NULL);
    EC_KEY_METHOD_set_sign(trustm_ctx.ec_key_method, orig_sign, NULL, trustm_ecdsa_sign);

    // Need to used OpenSSL verify as HW device has limited verification
    EC_KEY_METHOD_get_verify(trustm_ctx.ec_key_method, &orig_verify,&orig_verify_sig);
    EC_KEY_METHOD_set_verify(trustm_ctx.ec_key_method, orig_verify, orig_verify_sig);
            
    ret = ENGINE_set_EC(e, trustm_ctx.ec_key_method);
    
  }while(FALSE);

  TRUSTM_ENGINE_DBGFN("<");
  return ret;
}
