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

    TRUSTM_ENGINE_DBGFN(">");
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
	else	
	{
	    trustm_ctx.pubkeyHeaderLen = sizeof(eccheader384);
	    for (i=0; i < trustm_ctx.pubkeyHeaderLen;i++)
	    {
		public_key[i] = eccheader384[i];
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
	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
	return_status = optiga_lib_status;
	if (return_status != OPTIGA_LIB_SUCCESS)
	    break;
        
        //printf("length : %d\n",public_key_length+i);
        //trustmHexDump(public_key,public_key_length+i);
        //trustmWriteDER(public_key, public_key_length+i, "myTest.key");

        data = public_key;
	
	trustm_ctx.pubkeylen = public_key_length+i;
	for(j=0;j<trustm_ctx.pubkeylen;j++)
	{
	    trustm_ctx.pubkey[j] = *(data+j);
	}
	
        key = d2i_PUBKEY(NULL,(const unsigned char **)&data,public_key_length+i);
    } while (FALSE);

    // Capture OPTIGA Error
    if (return_status != OPTIGA_LIB_SUCCESS)
	key = NULL;

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
        while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
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
		j = trustm_ctx.pubkey[3] + 4;
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
	if (trustm_ctx.ec_flag == (0x01 & TRUSTM_ENGINE_FLAG_NEW))
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
		TRUSTM_ENGINE_DBGFN("No plubic Key found, Register Private Key only");
		//load dummy public key
		if(trustm_ctx.ec_key_curve == OPTIGA_ECC_CURVE_NIST_P_256)
		{
		    data = dummy_ec_public_key_256;
		    len = sizeof(dummy_ec_public_key_256);
		}
		else
		{
		    data = dummy_ec_public_key_384;
		    len = sizeof(dummy_ec_public_key_384);
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

#ifdef WORKAROUND		
    pal_os_event_arm();
#endif	 

    do 
    {  
	optiga_lib_status = OPTIGA_LIB_BUSY;
	return_status = optiga_crypt_ecdsa_sign(me_crypt,
						dgst,
						dgstlen,
						trustm_ctx.key_oid,
						(sig+2),
						&sig_len);
	if (OPTIGA_LIB_SUCCESS != return_status)
	    break;			
	//Wait until the optiga_util_read_metadata operation is completed
	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
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
    }while(FALSE);  
  
  
#ifdef WORKAROUND    
    pal_os_event_disarm();	
#endif

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
	if (	trustm_ctx.ec_key_method == NULL)
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
