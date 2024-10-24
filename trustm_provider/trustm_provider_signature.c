#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "trustm_provider_common.h"
#include "trustm_ec_key_helper.h"

typedef struct trustm_signature_ctx_str {
    const OSSL_CORE_HANDLE *core;

    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    // for digest operation
    trustm_digest_data_t *digest_data;

    // for RSA sign
    trustm_rsa_key_t *trustm_rsa_key;
    optiga_rsa_signature_scheme_t rsa_sign_scheme;

    // for EC sign
    trustm_ec_key_t *trustm_ec_key;

} trustm_signature_ctx_t;


// mutual for both rsa and ecc
static OSSL_FUNC_signature_newctx_fn trustm_signature_newctx;
static OSSL_FUNC_signature_freectx_fn trustm_signature_freectx;
static OSSL_FUNC_signature_dupctx_fn trustm_signature_dupctx;

static OSSL_FUNC_signature_get_ctx_params_fn trustm_signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn trustm_signature_gettable_ctx_params;
//

// rsa signature function declaration
static OSSL_FUNC_signature_sign_init_fn trustm_rsa_signature_sign_init;
static OSSL_FUNC_signature_sign_fn trustm_rsa_signature_sign;

static OSSL_FUNC_signature_digest_sign_init_fn trustm_rsa_signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn trustm_rsa_signature_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn trustm_rsa_signature_digest_sign_final;
static OSSL_FUNC_signature_digest_sign_fn trustm_rsa_signature_digest_sign;

static OSSL_FUNC_signature_digest_verify_final_fn trustm_rsa_signature_digest_verify_final;

static OSSL_FUNC_signature_set_ctx_params_fn trustm_rsa_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn trustm_rsa_signature_settable_ctx_params;

// ec signature function declaration
static OSSL_FUNC_signature_sign_init_fn trustm_ecdsa_signature_sign_init;
static OSSL_FUNC_signature_sign_fn trustm_ecdsa_signature_sign;

static OSSL_FUNC_signature_digest_sign_init_fn trustm_ecdsa_signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn trustm_ecdsa_signature_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn trustm_ecdsa_signature_digest_sign_final;
static OSSL_FUNC_signature_digest_sign_fn trustm_ecdsa_signature_digest_sign;

static OSSL_FUNC_signature_digest_verify_final_fn trustm_ecdsa_signature_digest_verify_final;

static OSSL_FUNC_signature_set_ctx_params_fn trustm_ecdsa_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn trustm_ecdsa_signature_settable_ctx_params;


static void *trustm_signature_newctx(void *provctx, const char *proq)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_signature_ctx_t *trustm_signature_ctx = OPENSSL_zalloc(sizeof(trustm_signature_ctx_t));

    if (trustm_signature_ctx == NULL)
        return NULL;
    
    trustm_signature_ctx->core = trustm_ctx->core;
    trustm_signature_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_signature_ctx->me_util = trustm_ctx->me_util;
    trustm_signature_ctx->trustm_rsa_key = NULL;
    trustm_signature_ctx->trustm_ec_key = NULL;

    // initialize digest data
    trustm_signature_ctx->digest_data = OPENSSL_zalloc(sizeof(trustm_digest_data_t));

    if (trustm_signature_ctx->digest_data == NULL)
    {
        OPENSSL_clear_free(trustm_signature_ctx, sizeof(trustm_signature_ctx_t));
        return NULL;
    }

    (trustm_signature_ctx->digest_data->hash_context).context_buffer = trustm_signature_ctx->digest_data->hash_context_buffer;
    (trustm_signature_ctx->digest_data->hash_context).context_buffer_length = sizeof(trustm_signature_ctx->digest_data->hash_context_buffer);
    (trustm_signature_ctx->digest_data->hash_context).hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;
    
    return trustm_signature_ctx;
}


static void trustm_signature_freectx(void *ctx)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;

    if (trustm_signature_ctx == NULL)
        return;

    if (trustm_signature_ctx->digest_data != NULL)
        OPENSSL_clear_free(trustm_signature_ctx->digest_data, sizeof(trustm_digest_data_t));

    OPENSSL_clear_free(trustm_signature_ctx, sizeof(trustm_signature_ctx_t));
}


static void *trustm_signature_dupctx(void *ctx)
{
    trustm_signature_ctx_t *src = ctx;
    trustm_signature_ctx_t *sctx = OPENSSL_zalloc(sizeof(trustm_signature_ctx_t));

    if (sctx == NULL)
        return NULL;

    sctx->digest_data = OPENSSL_zalloc(sizeof(trustm_digest_data_t));

    if (sctx->digest_data == NULL)
    {
        OPENSSL_clear_free(sctx, sizeof(trustm_signature_ctx_t));
        return NULL;
    }

    sctx->core = src->core;
    sctx->me_crypt = src->me_crypt;
    sctx->me_util = src->me_util;
    sctx->trustm_rsa_key = src->trustm_rsa_key;
    sctx->rsa_sign_scheme = src->rsa_sign_scheme;
    sctx->trustm_ec_key = src->trustm_ec_key;

    memcpy(sctx->digest_data->hash_context_buffer, src->digest_data->hash_context_buffer, OPTIGA_HASH_CONTEXT_LENGTH_SHA_256);
    memcpy(sctx->digest_data->digest, src->digest_data->digest, DIGEST_SIZE);

    (sctx->digest_data->hash_context).context_buffer = sctx->digest_data->hash_context_buffer;
    (sctx->digest_data->hash_context).context_buffer_length = sizeof(sctx->digest_data->hash_context_buffer);
    (sctx->digest_data->hash_context).hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;

    return sctx;
}

static int rsa_signature_scheme_init(trustm_signature_ctx_t *trustm_signature_ctx, const char *mdname)
{
    if (mdname == NULL)
    {
        // default to sha256 hash
        trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
        return 1;
    }

    if ((strcasecmp("SHA256", mdname) == 0) || (strcasecmp("SHA2-256", mdname) == 0))
        trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
    
    else if ((strcasecmp("SHA384", mdname) == 0) || (strcasecmp("SHA2-384", mdname) == 0))
        trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA384;

    else if ((strcasecmp("SHA512", mdname) == 0) || (strcasecmp("SHA2-512", mdname) == 0))
        trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA512;

    else 
    {
        TRUSTM_PROVIDER_ERRFN("Invalid hash algorithm\n");
        return 0;
    }

    return 1;
}

static int ecdsa_signature_scheme_init(trustm_signature_ctx_t *trustm_signature_ctx, const char *mdname)
{
    if (mdname == NULL)
    {
        // techincally with TrustM we can perform ECDSA without hashing
        return 1;
    }

    if ((strcasecmp("SHA256", mdname) == 0) || (strcasecmp("SHA2-256", mdname) == 0))
        return 1;

    else 
    {
        TRUSTM_PROVIDER_ERRFN("Invalid hash algorithm\n");
        return 0;
    }

    return 1;
}

static int trustm_rsa_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    trustm_signature_ctx->trustm_rsa_key = provkey;

    return (rsa_signature_scheme_init(trustm_signature_ctx, NULL)
            && trustm_rsa_signature_set_ctx_params(trustm_signature_ctx, params));
}

static int trustm_ecdsa_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    trustm_signature_ctx->trustm_ec_key = provkey;

    return (ecdsa_signature_scheme_init(trustm_signature_ctx, NULL)
            && trustm_ecdsa_signature_set_ctx_params(trustm_signature_ctx, params));
}

static int trustm_rsa_signature_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                                    const unsigned char *tbs, size_t tbslen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    TRUSTM_PROVIDER_DBG("sigsize : %d\n", sigsize);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_sign(trustm_signature_ctx->me_crypt,
                                        trustm_signature_ctx->rsa_sign_scheme,
                                        (uint8_t *)tbs,
                                        tbslen,
                                        trustm_signature_ctx->trustm_rsa_key->private_key_id,
                                        temp_sig,
                                        &temp_siglen,
                                        0x0000);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_rsa_signature_sign\n");
        return 0;
    }
    
    // copy signed buffer
    *siglen = temp_siglen;
    if (sig != NULL)
    {
        if (*siglen > sigsize)
        {
            TRUSTM_PROVIDER_ERRFN("Error output siglen : %d larger than sigsize : %d\n", *siglen, sigsize);
            return 0;
        }

        memcpy(sig, temp_sig, *siglen);
    }

    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_ecdsa_signature_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                                    const unsigned char *tbs, size_t tbslen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    TRUSTM_PROVIDER_DBG("sigsize : %d\n", sigsize);

    int byte_string_offset = (trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1
                            || trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521) 
                              ? 3 : 2;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdsa_sign(trustm_signature_ctx->me_crypt,
                                            tbs,
                                            tbslen,
                                            trustm_signature_ctx->trustm_ec_key->private_key_id,
                                            temp_sig+byte_string_offset,
                                            &temp_siglen);
    
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in optiga_crypt_ecdsa_sign\n");
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_ecdsa_signature_sign\n");
        return 0;
    }

    // formatting signature to byte string
    if (byte_string_offset == 2)
    {
        temp_sig[0] = 0x30; // byte string
        temp_sig[1] = temp_siglen;
    }

    else 
    {   trustm_ecc_r_s_padding_check(temp_sig+byte_string_offset,&temp_siglen);
        temp_sig[0] = 0x30;
        temp_sig[1] = 0x81;
        temp_sig[2] = temp_siglen;
    }

    // copy signed buffer
    *siglen = temp_siglen + byte_string_offset;
    if (sig != NULL)
    {
        if (*siglen > sigsize)
        {
            TRUSTM_PROVIDER_ERRFN("Error output siglen : %d larger than sigsize : %d\n", *siglen, sigsize);
            return 0;
        }

        memcpy(sig, temp_sig, *siglen);
    }

    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

// basically digest sign, can be used for both sign and verify operations
static int trustm_rsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    trustm_signature_ctx->trustm_rsa_key = provkey;
    optiga_lib_status_t return_status;


    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_start(trustm_signature_ctx->me_crypt, &(trustm_signature_ctx->digest_data->hash_context));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_start\n");
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_rsa_signature_digest_sign_init\n");
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE


    return (trustm_rsa_signature_set_ctx_params(trustm_signature_ctx, params)
            && rsa_signature_scheme_init(trustm_signature_ctx, mdname));
}

// basically digest sign, can be used for both sign and verify operations
static int trustm_ecdsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    trustm_signature_ctx->trustm_ec_key = provkey;
    optiga_lib_status_t return_status;


    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_start(trustm_signature_ctx->me_crypt, &(trustm_signature_ctx->digest_data->hash_context));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_start\n");
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_ecdsa_signature_digest_sign_init\n");
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE


    return (trustm_ecdsa_signature_set_ctx_params(trustm_signature_ctx, params)
            && ecdsa_signature_scheme_init(trustm_signature_ctx, mdname));
}

// basically digest update, can be used for both sign and verify operations
static int trustm_rsa_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;

    trustm_signature_ctx->digest_data->hash_data_host.buffer = data;
    trustm_signature_ctx->digest_data->hash_data_host.length = datalen;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_update(trustm_signature_ctx->me_crypt,
                                            &(trustm_signature_ctx->digest_data->hash_context),
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &(trustm_signature_ctx->digest_data->hash_data_host));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_update\n");
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_ecdsa_signature_digest_sign_update\n");
        return 0;
    }
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_finalize(trustm_signature_ctx->me_crypt,
                                               &(trustm_signature_ctx->digest_data->hash_context),
                                               trustm_signature_ctx->digest_data->digest);
    
    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_finalize\n");
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_ecdsa_signature_digest_sign_update\n");
        return 0;
    }
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

// basically digest update, can be used for both sign and verify operations
static int trustm_ecdsa_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;

    trustm_signature_ctx->digest_data->hash_data_host.buffer = data;
    trustm_signature_ctx->digest_data->hash_data_host.length = datalen;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_update(trustm_signature_ctx->me_crypt,
                                            &(trustm_signature_ctx->digest_data->hash_context),
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &(trustm_signature_ctx->digest_data->hash_data_host));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    }
    
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_finalize(trustm_signature_ctx->me_crypt,
                                               &(trustm_signature_ctx->digest_data->hash_context),
                                               trustm_signature_ctx->digest_data->digest);
    
    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    } 
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_rsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    digest_size = DIGEST_SIZE;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_sign(trustm_signature_ctx->me_crypt,
                                        trustm_signature_ctx->rsa_sign_scheme,
                                        trustm_signature_ctx->digest_data->digest,
                                        digest_size,
                                        trustm_signature_ctx->trustm_rsa_key->private_key_id,
                                        temp_sig,
                                        &temp_siglen,
                                        0x0000);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_rsa_sign\n");
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_rsa_signature_sign\n");
        return 0;
    }
    
    // copy signed buffer
    *siglen = temp_siglen;

    if (sig != NULL)
    {
        memcpy(sig, temp_sig, *siglen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_ecdsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    digest_size = DIGEST_SIZE;
    int byte_string_offset = (trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1
                            || trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521)
                            ? 3 : 2;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdsa_sign(trustm_signature_ctx->me_crypt,
                                        trustm_signature_ctx->digest_data->digest,
                                        digest_size,
                                        trustm_signature_ctx->trustm_ec_key->private_key_id,
                                        temp_sig+byte_string_offset,
                                        &temp_siglen);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecdsa_sign\n");
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_ecdsa_signature_sign\n");
        return 0;
    }
    
    // formatting signature to byte string
    if (byte_string_offset == 2)
    {
        temp_sig[0] = 0x30; // byte string
        temp_sig[1] = temp_siglen;
    }

    else 
    {   trustm_ecc_r_s_padding_check(temp_sig+byte_string_offset,&temp_siglen);
        temp_sig[0] = 0x30;
        temp_sig[1] = 0x81;
        temp_sig[2] = temp_siglen;
    }

    // copy signed buffer
    *siglen = temp_siglen + byte_string_offset;
    if (sig != NULL)
    {
        memcpy(sig, temp_sig, *siglen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}



static int trustm_rsa_signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    if (sig == NULL)
    {
        // estimating(?) size of the signature
        *siglen = temp_siglen;
        return *siglen > 0;
    }

    trustm_signature_ctx->digest_data->hash_data_host.buffer = data;
    trustm_signature_ctx->digest_data->hash_data_host.length = datalen;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_update(trustm_signature_ctx->me_crypt,
                                            &(trustm_signature_ctx->digest_data->hash_context),
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &(trustm_signature_ctx->digest_data->hash_data_host));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    }

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_finalize(trustm_signature_ctx->me_crypt,
                                               &(trustm_signature_ctx->digest_data->hash_context),
                                               trustm_signature_ctx->digest_data->digest);
    
    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    }

    digest_size = DIGEST_SIZE;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_sign(trustm_signature_ctx->me_crypt,
                                        trustm_signature_ctx->rsa_sign_scheme,
                                        trustm_signature_ctx->digest_data->digest,
                                        digest_size,
                                        trustm_signature_ctx->trustm_rsa_key->private_key_id,
                                        temp_sig,
                                        &temp_siglen,
                                        0x0000);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_rsa_sign\n");
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_rsa_signature_sign\n");
        return 0;
    }

    // copy signed buffer
    *siglen = temp_siglen;

    if (sig != NULL)
    {
        if (*siglen > sigsize)
        {
            TRUSTM_PROVIDER_ERRFN("Error output siglen : %d larger than sigsize : %d\n", *siglen, sigsize);
            return 0;
        }

        memcpy(sig, temp_sig, *siglen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}



static int trustm_ecdsa_signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;

    uint8_t temp_sig[500];
    uint16_t temp_siglen = sizeof(temp_sig);

    if (sig == NULL)
    {
        // estimating(?) size of the signature
        *siglen = temp_siglen;
        return *siglen > 0;
    }

    trustm_signature_ctx->digest_data->hash_data_host.buffer = data;
    trustm_signature_ctx->digest_data->hash_data_host.length = datalen;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_update(trustm_signature_ctx->me_crypt,
                                            &(trustm_signature_ctx->digest_data->hash_context),
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &(trustm_signature_ctx->digest_data->hash_data_host));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    }

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_finalize(trustm_signature_ctx->me_crypt,
                                               &(trustm_signature_ctx->digest_data->hash_context),
                                               trustm_signature_ctx->digest_data->digest);
    
    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        // add an error raise here
        return 0;
    }

    //Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        // add an error raise here
        return 0;
    }

    digest_size = DIGEST_SIZE;
    int byte_string_offset = (trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1
                            || trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521)
                            ? 3 : 2;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdsa_sign(trustm_signature_ctx->me_crypt,
                                        trustm_signature_ctx->digest_data->digest,
                                        digest_size,
                                        trustm_signature_ctx->trustm_ec_key->private_key_id,
                                        temp_sig+byte_string_offset,
                                        &temp_siglen);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecdsa_sign\n");
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error signing in trustm_ecdsa_signature_digest_sign\n");
        return 0;
    }

    // formatting signature to byte string
    if (byte_string_offset == 2)
    {
        temp_sig[0] = 0x30; // byte string
        temp_sig[1] = temp_siglen;
    }

    else 
    {   trustm_ecc_r_s_padding_check(temp_sig+byte_string_offset,&temp_siglen); 
        temp_sig[0] = 0x30;
        temp_sig[1] = 0x81;
        temp_sig[2] = temp_siglen;
    }

    // copy signed buffer
    *siglen = temp_siglen + byte_string_offset;
    if (sig != NULL)
    {
        if (*siglen > sigsize)
        {
            TRUSTM_PROVIDER_ERRFN("Error output siglen : %d larger than sigsize : %d\n", *siglen, sigsize);
            return 0;
        }

        memcpy(sig, temp_sig, *siglen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_rsa_signature_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;
    public_key_from_host_t public_key_details;
    
    uint8_t public_key_buffer[500];
    uint16_t public_key_buffer_length = sizeof(public_key_buffer);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    // convert public key to trustm's public key format
    public_key_buffer[0] = 0x03;
    if (trustm_signature_ctx->trustm_rsa_key->key_size == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
    {
        public_key_buffer[1] = 0x82;
        public_key_buffer[2] = 0x01;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[3] = 0x0f;
        
        else
            public_key_buffer[3] = 0x0e;
        
        public_key_buffer[4] = 0x00;
        public_key_buffer[5] = 0x30;
        public_key_buffer[6] = 0x82;
        public_key_buffer[7] = 0x01;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[8] = 0x0a;
        
        else
            public_key_buffer[8] = 0x09;
        
        public_key_buffer[9] = 0x02;
        public_key_buffer[10] = 0x82;
        public_key_buffer[11] =  0x01;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[12] = 0x01;

        else
            public_key_buffer[12] = 0x00;
        
        public_key_buffer_length = 13;
        
        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
        {
            public_key_buffer[13] = 0x00;
            memcpy(public_key_buffer+14, trustm_signature_ctx->trustm_rsa_key->modulus, trustm_signature_ctx->trustm_rsa_key->modulus_length);
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 14] = 0x02;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 15] = 0x03;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 16] = 0x01;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 17] = 0x00;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 18] = 0x01;
            public_key_buffer_length += 1 + trustm_signature_ctx->trustm_rsa_key->modulus_length + 5;
        }    

        else 
        {
            memcpy(public_key_buffer+13, trustm_signature_ctx->trustm_rsa_key->modulus, trustm_signature_ctx->trustm_rsa_key->modulus_length);
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 13] = 0x02;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 14] = 0x03;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 15] = 0x01;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 16] = 0x00;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 17] = 0x01;
            public_key_buffer_length += trustm_signature_ctx->trustm_rsa_key->modulus_length + 5; 
        }
    }

    else 
    {
        public_key_buffer[1] = 0x81;
        
        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[2] = 0x8e;
        
        else 
            public_key_buffer[2] = 0x8d;

        public_key_buffer[3] = 0x00;
        public_key_buffer[4] = 0x30;
        public_key_buffer[5] = 0x81;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[6] = 0x8a;
        
        else 
            public_key_buffer[6] = 0x89;

        public_key_buffer[7] = 0x02;
        public_key_buffer[8] = 0x81;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
            public_key_buffer[9] = 0x81;
        
        else 
            public_key_buffer[9] = 0x80;

        public_key_buffer_length = 10;

        if (trustm_signature_ctx->trustm_rsa_key->modulus[0] > 0x7F)
        {
            public_key_buffer[10] = 0x00;
            memcpy(public_key_buffer+11, trustm_signature_ctx->trustm_rsa_key->modulus, trustm_signature_ctx->trustm_rsa_key->modulus_length);
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 11] = 0x02;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 12] = 0x03;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 13] = 0x01;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 14] = 0x00;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 15] = 0x01;
            public_key_buffer_length += 1 + trustm_signature_ctx->trustm_rsa_key->modulus_length + 5;
        }

        else 
        {
            memcpy(public_key_buffer+10, trustm_signature_ctx->trustm_rsa_key->modulus, trustm_signature_ctx->trustm_rsa_key->modulus_length);
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 10] = 0x02;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 11] = 0x03;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 12] = 0x01;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 13] = 0x00;
            public_key_buffer[trustm_signature_ctx->trustm_rsa_key->modulus_length + 14] = 0x01;
            public_key_buffer_length += trustm_signature_ctx->trustm_rsa_key->modulus_length + 5;
        }     
    }

    digest_size = DIGEST_SIZE;
    public_key_details.public_key = public_key_buffer;
    public_key_details.length = public_key_buffer_length;
    public_key_details.key_type = (uint8_t)trustm_signature_ctx->trustm_rsa_key->key_size;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_verify(trustm_signature_ctx->me_crypt,
                                            trustm_signature_ctx->rsa_sign_scheme,
                                            trustm_signature_ctx->digest_data->digest,
                                            digest_size,
                                            (uint8_t *)sig,
                                            (uint16_t)siglen,
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &public_key_details,
                                            0x0000);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error verifying in optiga_crypt_rsa_verify\n Error code: 0x%.4x\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error verifying in trustm_rsa_signature_digest_verify_final\nError code: 0x%.4x\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_ecdsa_signature_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    optiga_lib_status_t return_status;
    uint8_t digest_size;
    public_key_from_host_t public_key_details;

    void *uncompressed_pubkey_buffer;
    uint16_t uncompressed_pubkey_buffer_length;
    uint8_t pubkey_buffer[300];
    uint16_t pubkey_buffer_length;

    uint8_t input_sig[300];
    uint16_t input_sig_len = sizeof(input_sig);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_signature_ctx->me_crypt = me_crypt;

    // getting public key from import 
    uncompressed_pubkey_buffer_length = trustm_ec_point_to_uncompressed_buffer(trustm_signature_ctx->trustm_ec_key, &uncompressed_pubkey_buffer);

    pubkey_buffer[0] = 0x03;

    if (trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521
        || trustm_signature_ctx->trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)
    {
        pubkey_buffer[1] = 0x81;
        pubkey_buffer[2] = uncompressed_pubkey_buffer_length + 1;
        pubkey_buffer[3] = 0x00;

        // copy uncompressed form to buffer 
        memcpy(pubkey_buffer+4, uncompressed_pubkey_buffer, uncompressed_pubkey_buffer_length);

        pubkey_buffer_length = uncompressed_pubkey_buffer_length + 4;
    }

    else 
    {
        pubkey_buffer[1] = uncompressed_pubkey_buffer_length + 1;
        pubkey_buffer[2] = 0x00;

        // copy uncompressed form to buffer
        memcpy(pubkey_buffer+3, uncompressed_pubkey_buffer, uncompressed_pubkey_buffer_length);   
    
        pubkey_buffer_length = uncompressed_pubkey_buffer_length + 3;
    }

    // free temp buffer
    OPENSSL_free(uncompressed_pubkey_buffer);

    // convert OpenSSL signature to Trust M input signature
    // if the signature is longer than 0x80 bytes
    if (sig[1] > 0x80)
    {
        memcpy(input_sig, sig+3, siglen-3);
        input_sig_len = siglen - 3;
    }

    // else skip first 2 bytes of OSSL input signature
    else 
    {
        memcpy(input_sig, sig+2, siglen-2);
        input_sig_len = siglen - 2;
    }

    digest_size = DIGEST_SIZE;
    public_key_details.public_key = pubkey_buffer;
    public_key_details.length = pubkey_buffer_length;
    public_key_details.key_type = (uint8_t)trustm_signature_ctx->trustm_ec_key->key_curve;

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdsa_verify(trustm_signature_ctx->me_crypt,
                                            trustm_signature_ctx->digest_data->digest,
                                            digest_size,
                                            (uint8_t *)input_sig,
                                            (uint16_t)input_sig_len,
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &public_key_details);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error verifying in optiga_crypt_ecdsa_verify\n Error code: 0x%.4x\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }
    // Wait until the optiga_util_read_metadata operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error verifying in trustm_ecdsa_signature_digest_verify_final\nError code: 0x%.4x\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return 1;
}

static int trustm_rsa_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        else 
        {
            if ((strcasecmp("SHA256", p->data) == 0) || ((strcasecmp("RSA+SHA256", p->data) == 0)))
                trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
    
             else if (strcasecmp("SHA384", p->data) == 0)
                trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA384;

            else if (strcasecmp("SHA512", p->data) == 0)
                trustm_signature_ctx->rsa_sign_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA512;

            else 
            {
                TRUSTM_PROVIDER_ERRFN("Invalid hash algorithm\n");
                return 0;
            }
        }
    }

    return 1;
}

static int trustm_ecdsa_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        else 
        {
            if ((strcasecmp("SHA256", p->data) == 0) || ((strcasecmp("SHA2-256", p->data) == 0)))
                return 1;

            else 
            {
                TRUSTM_PROVIDER_ERRFN("Invalid hash algorithm\n");
                return 0;
            }
        }
    }

    return 1;
}


static const OSSL_PARAM * trustm_rsa_signature_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}


static const OSSL_PARAM * trustm_ecdsa_signature_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static int trustm_signature_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    trustm_signature_ctx_t *trustm_signature_ctx = ctx;
    X509_ALGOR* x509_algor;
    ASN1_OBJECT *oid;
    OSSL_PARAM *p;

    x509_algor = X509_ALGOR_new();
    if (x509_algor == NULL)
        return 0;

    // if the signature algorithm is RSA
    if (trustm_signature_ctx->trustm_rsa_key != NULL)
    {
        switch (trustm_signature_ctx->rsa_sign_scheme) {
        case OPTIGA_RSASSA_PKCS1_V15_SHA256:
            oid = OBJ_nid2obj(NID_sha256WithRSAEncryption);
            break;

        case OPTIGA_RSASSA_PKCS1_V15_SHA384:
            oid = OBJ_nid2obj(NID_sha384WithRSAEncryption);
            break;

        case OPTIGA_RSASSA_PKCS1_V15_SHA512:
            oid = OBJ_nid2obj(NID_sha512WithRSAEncryption);
            break;

        default:
            return 0;
        }
        
        X509_ALGOR_set0(x509_algor, oid, V_ASN1_NULL, NULL);
    }

    // if the signature algorithm is ecdsa
    if (trustm_signature_ctx->trustm_ec_key != NULL)
    {
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA256);
        X509_ALGOR_set0(x509_algor, oid, V_ASN1_NULL, NULL);
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL)
    {
        unsigned char *aid = NULL;
        int aid_len, r;

        aid_len = i2d_X509_ALGOR(x509_algor, &aid);
        X509_ALGOR_free(x509_algor);

        r = OSSL_PARAM_set_octet_string(p, aid, aid_len);
        free(aid);
        return r;
    }


    return 1;
}

static const OSSL_PARAM *trustm_signature_gettable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

const OSSL_DISPATCH trustm_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void(*)(void))trustm_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void(*)(void))trustm_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void(*)(void))trustm_signature_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void(*)(void))trustm_rsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void(*)(void))trustm_rsa_signature_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void(*)(void))trustm_rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void(*)(void))trustm_rsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void(*)(void))trustm_rsa_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void(*)(void))trustm_rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void(*)(void))trustm_rsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void(*)(void))trustm_rsa_signature_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void(*)(void))trustm_rsa_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void(*)(void))trustm_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))trustm_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void(*)(void))trustm_rsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))trustm_rsa_signature_settable_ctx_params },
    { 0, NULL }
};


const OSSL_DISPATCH trustm_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void(*)(void))trustm_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void(*)(void))trustm_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void(*)(void))trustm_signature_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void(*)(void))trustm_ecdsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void(*)(void))trustm_ecdsa_signature_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void(*)(void))trustm_ecdsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void(*)(void))trustm_ecdsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void(*)(void))trustm_ecdsa_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void(*)(void))trustm_ecdsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void(*)(void))trustm_ecdsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void(*)(void))trustm_ecdsa_signature_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void(*)(void))trustm_ecdsa_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void(*)(void))trustm_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))trustm_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void(*)(void))trustm_ecdsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))trustm_ecdsa_signature_settable_ctx_params },
    { 0, NULL }
};
