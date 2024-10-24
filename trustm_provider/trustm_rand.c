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
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_rand_ctx_t *trustm_rand_ctx = OPENSSL_zalloc(sizeof(trustm_rand_ctx_t));

    if (trustm_rand_ctx == NULL) {
        return NULL;
    }

    trustm_rand_ctx->core = trustm_ctx->core;
    trustm_rand_ctx->me_crypt = trustm_ctx->me_crypt;

    return trustm_rand_ctx;
}

static void trustm_rand_freectx(void *ctx) 
{
    trustm_rand_ctx_t *trustm_rand_ctx = ctx;

    if (trustm_rand_ctx == NULL) {
        return;
    }
        
    OPENSSL_clear_free(trustm_rand_ctx, sizeof(trustm_rand_ctx_t));
    CRYPTO_THREAD_lock_free(trustm_rand_ctx->lock);
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
    int i,j,k;
    uint8_t tempbuf[MAX_RAND_INPUT];    
    int ret = TRUSTM_PROVIDER_FAIL;
    
    i = outlen % MAX_RAND_INPUT; // max random number output, find the reminder
    j = (outlen - i)/MAX_RAND_INPUT; // Get the count 
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_rand_ctx->me_crypt = me_crypt;

    do 
    {   
        k = 0;
        if(i > 0)  
        {
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_random(trustm_rand_ctx->me_crypt, 
                                OPTIGA_RNG_TYPE_TRNG, 
                                tempbuf,
                                MAX_RAND_INPUT);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;			
            //Wait until the optiga_util_read_metadata operation is completed
            trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
            {
                TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
                break;
            }

            for (k=0;k<i;k++)
            {
                *(out+k) = tempbuf[k]; 
            }
        }

        for(;j>0;j--)  
        {
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_random(trustm_rand_ctx->me_crypt, 
                                OPTIGA_RNG_TYPE_TRNG, 
                                (out+k),
                                MAX_RAND_INPUT);
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
                break;			
            }
            //Wait until the optiga_util_read_metadata operation is completed
            trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
            {
                TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
                break;
            }
            k += (MAX_RAND_INPUT);
        }

        ret = TRUSTM_PROVIDER_SUCCESS;
    }while(FALSE);
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

	// Capture OPTIGA Error
	if (return_status != OPTIGA_LIB_SUCCESS) 
    {
		trustmPrintErrorCode(return_status);
        TRUSTM_ERROR_raise(trustm_rand_ctx->core, TRUSTM_ERR_CANNOT_GET_RANDOM);
    }
    // if fail returns all zero
    if (ret != TRUSTM_PROVIDER_SUCCESS)
    {
        TRUSTM_PROVIDER_DBGFN("error ret 0!!!\n");
        for(i=0;i<outlen;i++)
        {
            *(out+i) = 0;
        }
    }
    
    TRUSTM_PROVIDER_DBGFN("<");    
    return ret;
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
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int
trustm_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 256))
        return 0;

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
