#include <string.h>


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>


#include <sys/ipc.h>
#include <sys/shm.h>

#include "pal_ifx_i2c_config.h"
#include "trustm_helper.h"
#include "optiga_lib_common.h"
#include "pal_shared_mutex.h"

#include "trustm_provider_common.h"


typedef struct trustm_rand_ctx_str
{
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t * me_crypt;
    CRYPTO_RWLOCK *lock;
} trustm_rand_ctx_t;

static OSSL_FUNC_rand_newctx_fn trustm_rand_newctx;
static OSSL_FUNC_rand_freectx_fn trustm_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn trustm_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn trustm_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn trustm_rand_generate;
static OSSL_FUNC_rand_enable_locking_fn trustm_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn trustm_rand_lock;
static OSSL_FUNC_rand_unlock_fn trustm_rand_unlock;
static OSSL_FUNC_rand_gettable_ctx_params_fn trustm_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn trustm_rand_get_ctx_params;




static void * trustm_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) 
{
    TRUSTM_PROVIDER_DBGFN(">"); 
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_rand_ctx_t *trustm_rand_ctx = OPENSSL_zalloc(sizeof(trustm_rand_ctx_t));
    if (trustm_rand_ctx == NULL) {
        return NULL;
    }

    trustm_rand_ctx->core = trustm_ctx->core;
    trustm_rand_ctx->me_crypt = trustm_ctx->me_crypt;
	TRUSTM_PROVIDER_DBGFN("<"); 
    return trustm_rand_ctx;
}

static void trustm_rand_freectx(void *ctx) 
{
    trustm_rand_ctx_t *trustm_rand_ctx = ctx;
    TRUSTM_PROVIDER_DBGFN(">"); 
    if (trustm_rand_ctx == NULL) {
        return;
    }
    
    CRYPTO_THREAD_lock_free(trustm_rand_ctx->lock);    
    OPENSSL_clear_free(trustm_rand_ctx, sizeof(trustm_rand_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<"); 
}

static int trustm_rand_instantiate(void *ctx, unsigned int strength,
                      int prediction_resistance,
                      const unsigned char *pstr, size_t pstr_len,
                      const OSSL_PARAM params[])
{
    return 1;
}

static int
trustm_rand_uninstantiate(void *ctx)
{
    return 1;
}


static int
trustm_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                   unsigned int strength, int prediction_resistance,
                   const unsigned char *adin, size_t adinlen)
{
    
    #define MAX_RAND_INPUT 256
    trustm_rand_ctx_t * trustm_rand_ctx = ctx;

    optiga_lib_status_t return_status;
    uint8_t tempbuf[MAX_RAND_INPUT]; 
    size_t remaining = outlen; 
    size_t offset = 0;   
    
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_rand_ctx->me_crypt = me_crypt;
    while (remaining > 0) 
    {
        size_t bytes_to_generate = (remaining > MAX_RAND_INPUT) ? MAX_RAND_INPUT : remaining;

        trustm_crypt_ShieldedConnection();
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_random(trustm_rand_ctx->me_crypt,
                                            OPTIGA_RNG_TYPE_TRNG,
                                            tempbuf,
                                            bytes_to_generate);

        if (OPTIGA_LIB_SUCCESS != return_status) 
        {
            TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
            goto error; 
        }

        //Wait until the optiga_crypt_random operation is completed
		trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
            goto error; 
        }

        memcpy(out + offset, tempbuf, bytes_to_generate);
        offset += bytes_to_generate;
        remaining -= bytes_to_generate;
    }
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE  
    TRUSTM_PROVIDER_DBGFN("<");    
    return 1;
 
error:
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    return 0;  
    
    #undef MAX_RAND_INPUT 
}


static int
trustm_rand_enable_locking(void *ctx)
{
    trustm_rand_ctx_t *trustm_rand_ctx = ctx;
    trustm_rand_ctx->lock = CRYPTO_THREAD_lock_new();
    return 1;
}

static int
trustm_rand_lock(void *ctx)
{
    trustm_rand_ctx_t *trustm_rand_ctx = ctx;

    if (trustm_rand_ctx == NULL || trustm_rand_ctx->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(trustm_rand_ctx->lock);
}


static void
trustm_rand_unlock(void *ctx)
{
    trustm_rand_ctx_t *trustm_rand_ctx = ctx;

    if (trustm_rand_ctx == NULL || trustm_rand_ctx->lock == NULL)
        return;
    CRYPTO_THREAD_unlock(trustm_rand_ctx->lock);
}


static const OSSL_PARAM *
trustm_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int
trustm_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    TRUSTM_PROVIDER_DBGFN(">");
    TRACE_PARAMS("RAND GET_CTX_PARAMS", params);
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    /* always ready */
    if (p != NULL && !OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;    
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 256))
        return 0;
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

const OSSL_DISPATCH trustm_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))trustm_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))trustm_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))trustm_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))trustm_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))trustm_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))trustm_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))trustm_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))trustm_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))trustm_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))trustm_rand_get_ctx_params },
    { 0, NULL }
};
