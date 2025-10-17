#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "pal_ifx_i2c_config.h"
#include "trustm_helper.h"
#include "optiga_lib_common.h"

#include "trustm_provider_common.h"



typedef struct trustm_digest_ctx_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t * me_crypt;
    trustm_digest_data_t * data;
} trustm_digest_ctx_t;


static OSSL_FUNC_digest_newctx_fn trustm_digest_newctx;
static OSSL_FUNC_digest_freectx_fn trustm_digest_freectx;
static OSSL_FUNC_digest_dupctx_fn trustm_digest_dupctx;
static OSSL_FUNC_digest_init_fn trustm_digest_init;
static OSSL_FUNC_digest_update_fn trustm_digest_update;
static OSSL_FUNC_digest_final_fn trustm_digest_final;
//static OSSL_FUNC_digest_digest_fn trustm_digest_digest;
static OSSL_FUNC_digest_gettable_params_fn trustm_digest_gettable_params;
static OSSL_FUNC_digest_get_params_fn trustm_digest_get_params;

static void *trustm_digest_newctx(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_digest_ctx_t *trustm_digest_ctx = OPENSSL_zalloc(sizeof(trustm_digest_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_digest_ctx == NULL)
        return NULL;

    trustm_digest_ctx->core = trustm_ctx->core;
    trustm_digest_ctx->me_crypt = trustm_ctx->me_crypt;

    trustm_digest_ctx->data = OPENSSL_zalloc(sizeof(trustm_digest_data_t));

    if (trustm_digest_ctx->data == NULL) 
    {
        OPENSSL_clear_free(trustm_digest_ctx, sizeof(trustm_digest_ctx_t));
        return NULL;
    }

    (trustm_digest_ctx->data->hash_context).context_buffer = trustm_digest_ctx->data->hash_context_buffer;
    (trustm_digest_ctx->data->hash_context).context_buffer_length = sizeof(trustm_digest_ctx->data->hash_context_buffer);
    (trustm_digest_ctx->data->hash_context).hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_digest_ctx;
}

static void trustm_digest_freectx(void *ctx)
{
    trustm_digest_ctx_t *trustm_digest_ctx = ctx;

    if (trustm_digest_ctx == NULL)
        return;

    if (trustm_digest_ctx->data != NULL)
        OPENSSL_clear_free(trustm_digest_ctx->data, sizeof(trustm_digest_data_t));

    OPENSSL_clear_free(trustm_digest_ctx, sizeof(trustm_digest_ctx_t));
}


static void *trustm_digest_dupctx(void *ctx)
{
    trustm_digest_ctx_t *src = ctx;
    trustm_digest_ctx_t *dstctx = OPENSSL_zalloc(sizeof(trustm_digest_ctx_t));

    if (dstctx == NULL)
        return NULL;

    dstctx->core = src->core;
    dstctx->me_crypt = src->me_crypt;

    dstctx->data = OPENSSL_zalloc(sizeof(trustm_digest_data_t));

    if (dstctx->data == NULL) 
    {
        OPENSSL_clear_free(dstctx, sizeof(trustm_digest_ctx_t));
        return NULL;
    }

    memcpy(dstctx->data->hash_context_buffer, src->data->hash_context_buffer, OPTIGA_HASH_CONTEXT_LENGTH_SHA_256);
    memcpy(dstctx->data->digest, src->data->digest, DIGEST_SIZE);

    (dstctx->data->hash_context).context_buffer = dstctx->data->hash_context_buffer;
    (dstctx->data->hash_context).context_buffer_length = sizeof(dstctx->data->hash_context_buffer);
    (dstctx->data->hash_context).hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;

    return dstctx;
}

static int trustm_digest_init(void *ctx, const OSSL_PARAM params[])
{
    trustm_digest_ctx_t *trustm_digest_ctx = ctx;
    optiga_lib_status_t return_status;
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_digest_ctx->me_crypt = me_crypt;

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_start(trustm_digest_ctx->me_crypt, &(trustm_digest_ctx->data->hash_context));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_start\nError code : 0x%.4X\n", return_status);
        goto error;
    }

    //Wait until the optiga_crypt_hash_start operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_digest_init\nError code : 0x%.4X\n", return_status);
        goto error;
    }
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
error:
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE   
    return 0;
}

static int trustm_digest_update(void *ctx, const unsigned char *in, size_t inl)
{
    trustm_digest_ctx_t *trustm_digest_ctx = ctx;
    optiga_lib_status_t return_status;
    TRUSTM_PROVIDER_DBGFN(">");
    trustm_digest_ctx->data->hash_data_host.buffer = in;
    trustm_digest_ctx->data->hash_data_host.length = inl;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_digest_ctx->me_crypt = me_crypt;
    // Check if hash context needs reinitialization
    if (trustm_digest_ctx->data->hash_context.context_buffer[0] == 0) {
        TRUSTM_PROVIDER_DBGFN("Hash context reinitializing\n");
        trustm_crypt_ShieldedConnection();
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_hash_start(trustm_digest_ctx->me_crypt, 
                                               &(trustm_digest_ctx->data->hash_context));
        if (return_status != OPTIGA_LIB_SUCCESS) {
            TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_start\nError code : 0x%.4X\n", return_status);
            goto error;
        }
        trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        if (optiga_lib_status != OPTIGA_LIB_SUCCESS) {
            TRUSTM_PROVIDER_ERRFN("Error in Hash context reinitializing\nError code : 0x%.4X\n", return_status);
            goto error;
        }
    }
    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_update(trustm_digest_ctx->me_crypt,
                                            &(trustm_digest_ctx->data->hash_context),
                                            OPTIGA_CRYPT_HOST_DATA,
                                            &(trustm_digest_ctx->data->hash_data_host));

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_update\nError code : 0x%.4X\n", return_status);
        goto error;
    }

    //Wait until the optiga_crypt_hash_update operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_digest_update\nError code : 0x%.4X\n", return_status);
        goto error;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
error:
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    return 0;
}

static int trustm_digest_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    trustm_digest_ctx_t *trustm_digest_ctx = ctx;
    optiga_lib_status_t return_status;
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_digest_ctx->me_crypt = me_crypt;

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_hash_finalize(trustm_digest_ctx->me_crypt,
                                               &(trustm_digest_ctx->data->hash_context),
                                               trustm_digest_ctx->data->digest);
    
    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_hash_final\nError code : 0x%.4X\n", return_status);
        goto error;
    }

    //Wait until the optiga_crypt_hash_final operation is completed
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_digest_final\nError code : 0x%.4X\n", return_status);
        goto error;
    }

    *outl = DIGEST_SIZE;

    if (out != NULL) 
    {
        if (*outl > outsz) 
            goto error;
        
        memcpy(out, trustm_digest_ctx->data->digest, *outl);
    }
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
error:
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    return 0;
}


static const OSSL_PARAM * trustm_digest_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

static int trustm_digest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 512/8))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, DIGEST_SIZE))
        return 0;

    return 1;
}

const OSSL_DISPATCH trustm_digest_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void(*)(void))trustm_digest_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void(*)(void))trustm_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void(*)(void))trustm_digest_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (void(*)(void))trustm_digest_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void(*)(void))trustm_digest_update },
    { OSSL_FUNC_DIGEST_FINAL, (void(*)(void))trustm_digest_final },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void(*)(void))trustm_digest_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void(*)(void))trustm_digest_get_params },
    { 0, NULL }
};
