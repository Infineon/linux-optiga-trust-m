#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

#include "trustm_provider_common.h"


#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp  _stricmp
#endif

typedef struct trustm_rsa_asymcipher_ctx_str {
    const OSSL_CORE_HANDLE *core;

    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    trustm_rsa_key_t *trustm_rsa_key;
    optiga_rsa_encryption_scheme_t encryption_scheme;

    uint8_t encrypted_message[2048];
    uint16_t encrypted_message_length;

    uint8_t decrypted_message[2048];
    uint16_t decrypted_message_length;
} trustm_rsa_asymcipher_ctx_t;


static OSSL_FUNC_asym_cipher_newctx_fn rsa_asymcipher_newctx;
static OSSL_FUNC_asym_cipher_decrypt_init_fn rsa_asymcipher_decrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn rsa_asymcipher_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_fn rsa_asymcipher_decrypt;
static OSSL_FUNC_asym_cipher_freectx_fn rsa_asymcipher_freectx;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn rsa_asymcipher_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn rsa_asymcipher_settable_ctx_params;

static void *rsa_asymcipher_newctx(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = OPENSSL_zalloc(sizeof(trustm_rsa_asymcipher_ctx_t));

    if (trustm_rsa_asymcipher_ctx == NULL)
        return NULL;

    trustm_rsa_asymcipher_ctx->core = trustm_ctx->core;
    trustm_rsa_asymcipher_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_rsa_asymcipher_ctx->me_util = trustm_ctx->me_util;
    trustm_rsa_asymcipher_ctx->trustm_rsa_key = NULL;
    trustm_rsa_asymcipher_ctx->encryption_scheme = OPTIGA_RSAES_PKCS1_V15;
    trustm_rsa_asymcipher_ctx->encrypted_message_length = sizeof(trustm_rsa_asymcipher_ctx->encrypted_message);
    trustm_rsa_asymcipher_ctx->decrypted_message_length = sizeof(trustm_rsa_asymcipher_ctx->decrypted_message);

    return trustm_rsa_asymcipher_ctx;
}


static int rsa_asymcipher_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = ctx;
    trustm_rsa_asymcipher_ctx->me_crypt = me_crypt;
    // assign key
    trustm_rsa_asymcipher_ctx->trustm_rsa_key = (trustm_rsa_key_t *) provkey;

    return rsa_asymcipher_set_ctx_params(trustm_rsa_asymcipher_ctx, params);
}

static int rsa_asymcipher_encrypt(void *ctx, unsigned char *out, size_t *outlen, 
                                    size_t outsize, const unsigned char *in, size_t inlen)
{
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = ctx;
    
    optiga_lib_status_t return_status;
    public_key_from_host_t public_key_from_host;


    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE

    public_key_from_host.public_key = (uint8_t *)(trustm_rsa_asymcipher_ctx->trustm_rsa_key->public_key +  
                                                trustm_rsa_asymcipher_ctx->trustm_rsa_key->public_key_header_length);
    public_key_from_host.length = (trustm_rsa_asymcipher_ctx->trustm_rsa_key->public_key_length) - 
                                    (trustm_rsa_asymcipher_ctx->trustm_rsa_key->public_key_header_length);
    public_key_from_host.key_type = trustm_rsa_asymcipher_ctx->trustm_rsa_key->key_size;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_encrypt_message(trustm_rsa_asymcipher_ctx->me_crypt, 
                                                    trustm_rsa_asymcipher_ctx->encryption_scheme,
                                                    (uint8_t *)in,
                                                    (uint16_t)inlen,
                                                    NULL,
                                                    0,
                                                    OPTIGA_CRYPT_HOST_DATA,
                                                    &public_key_from_host,
                                                    trustm_rsa_asymcipher_ctx->encrypted_message,
                                                    &trustm_rsa_asymcipher_ctx->encrypted_message_length);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        printf("Error encrypting message with RSA");
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
        return 0;
    }

    // wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Error encrypting message with RSA");
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
        return 0;
    }

    *outlen = trustm_rsa_asymcipher_ctx->encrypted_message_length;
    
    if (out != NULL)
    {
        if (*outlen > outsize)
        {
            printf("Error outlen : %d is larger than outsize : %d\n", *outlen, outsize);
            TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
            return 0;
        }

        memcpy(out, trustm_rsa_asymcipher_ctx->encrypted_message, *outlen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}


static int rsa_asymcipher_decrypt(void *ctx, unsigned char *out, size_t *outlen, 
                                    size_t outsize, const unsigned char *in, size_t inlen)
{
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = ctx;
    optiga_lib_status_t return_status;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_decrypt_and_export(trustm_rsa_asymcipher_ctx->me_crypt,
                                                        trustm_rsa_asymcipher_ctx->encryption_scheme,
                                                        (uint8_t *)in,
                                                        (uint16_t) inlen,
                                                        NULL,
                                                        0,
                                                        trustm_rsa_asymcipher_ctx->trustm_rsa_key->private_key_id,
                                                        trustm_rsa_asymcipher_ctx->decrypted_message,
                                                        &(trustm_rsa_asymcipher_ctx->decrypted_message_length));
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        printf("Error decrypting message with RSA.\nError code : %.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
        return 0;
    }

    // wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Error decrypting message with RSA.\nError code : %.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
        return 0;
    }

    *outlen = trustm_rsa_asymcipher_ctx->decrypted_message_length;

    if (out != NULL)
    {
        if (*outlen > outsize)
        {
            printf("Error outlen : %d is larger than outsize : %d\n", *outlen, outsize);
            TRUSTM_PROVIDER_SSL_MUTEX_RELEASE;
            return 0;
        }

        memcpy(out, trustm_rsa_asymcipher_ctx->decrypted_message, *outlen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static void rsa_asymcipher_freectx(void *ctx)
{
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = ctx;

    if (trustm_rsa_asymcipher_ctx == NULL)
        return;

    OPENSSL_clear_free(trustm_rsa_asymcipher_ctx, sizeof(trustm_rsa_asymcipher_ctx_t));
}

static int rsa_asymcipher_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_rsa_asymcipher_ctx_t *trustm_rsa_asymcipher_ctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        int pad_mode = 0;

        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            
            if (pad_mode == RSA_PKCS1_PADDING || pad_mode == RSA_PKCS1_WITH_TLS_PADDING)
                trustm_rsa_asymcipher_ctx->encryption_scheme = OPTIGA_RSAES_PKCS1_V15;

            else 
                return 0;
            
            break;

        case OSSL_PARAM_UTF8_STRING:
            if (!strcasecmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15))
                trustm_rsa_asymcipher_ctx->encryption_scheme = OPTIGA_RSAES_PKCS1_V15;
            
            else
                return 0;
            
            break;

        default:
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *rsa_asymcipher_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_END
    };

    return known_settable_ctx_params;
}

const OSSL_DISPATCH trustm_rsa_asymcipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void(*)(void))rsa_asymcipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void(*)(void))rsa_asymcipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void(*)(void))rsa_asymcipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void(*)(void))rsa_asymcipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void(*)(void))rsa_asymcipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void(*)(void))rsa_asymcipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void(*)(void))rsa_asymcipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void(*)(void))rsa_asymcipher_settable_ctx_params },
    { 0, NULL }
};
