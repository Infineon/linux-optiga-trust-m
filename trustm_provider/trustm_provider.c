#include <string.h>


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>


#include <sys/ipc.h>
#include <sys/shm.h>

#include "optiga/pal/pal_ifx_i2c_config.h"
#include "trustm_helper.h"
#include "trustm_helper_ipc_lock.h"

#include "trustm_provider_common.h"


///////////////////////////////// trustm hardware related /////////////////////////////////
#ifdef WORKAROUND
	extern void pal_os_event_disarm(void);
	extern void pal_os_event_arm(void);
	extern void pal_os_event_destroy1(void);
#endif

extern void pal_os_event_disarm(void);

shared_mutex_t trustm_eng_mutex;
shared_mutex_t ssl_mutex;


/**********************************************************************
* provider_optiga_util_callback()
**********************************************************************/
void provider_optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    TRUSTM_HELPER_DBGFN("optiga_lib_status: %x\n",optiga_lib_status);
}

/**********************************************************************
* provider_optiga_crypt_callback()
**********************************************************************/
void provider_optiga_crypt_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}

/**********************************************************************
* trustmProvider_WaitForCompletion()
**********************************************************************/
optiga_lib_status_t trustmProvider_WaitForCompletion(uint16_t wait_time)
{
    uint16_t tickcount;
     
    tickcount=0;
    do
    {
        mssleep(1);
        tickcount++;
        if (tickcount >= wait_time)
        {
            TRUSTM_PROVIDER_ERRFN("Fail : Optiga Busy Time Out:%d\n",tickcount);
            return OPTIGA_LIB_BUSY;
        }
         
    }while (optiga_lib_status == OPTIGA_LIB_BUSY);
    TRUSTM_PROVIDER_DBGFN(" max wait_time:%d, Tick Counter: %d", wait_time,tickcount);
    return optiga_lib_status;
    
}


/**********************************************************************
* trustmProvider_Open()
**********************************************************************/
optiga_lib_status_t trustmProvider_Open(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_PROVIDER_DBGFN(">");

    do
    {
        
        //Create an instance of optiga_util to open the application on OPTIGA.
        trustm_ipc_acquire(&trustm_eng_mutex,"/trustm-mutex");
        if (me_util == NULL)
        {
            me_util = optiga_util_create(0, provider_optiga_util_callback, NULL);
            if (NULL == me_util)
            {
                TRUSTM_PROVIDER_ERRFN("Fail : optiga_util_create\n");
                return_status = OPTIGA_UTIL_ERROR;
                break;
            }
            TRUSTM_PROVIDER_DBGFN("optiga_util_create OK \n");
        }else
        {   TRUSTM_PROVIDER_DBGFN("TrustM util instance exists. \n");
        }

        if(me_crypt ==NULL)
        {
            me_crypt = optiga_crypt_create(0, provider_optiga_crypt_callback, NULL);
            if (NULL == me_crypt)
            {
                TRUSTM_PROVIDER_ERRFN("Fail : optiga_crypt_create\n");
                return_status = OPTIGA_CRYPT_ERROR;
                break;
            }
            TRUSTM_PROVIDER_DBGFN("optiga_crypt_create OK \n");
        }else
        {
            TRUSTM_PROVIDER_DBGFN("TrustM crypt instance exists. \n");
        }
        TRUSTM_WORKAROUND_TIMER_ARM;
        return_status = OPTIGA_LIB_SUCCESS;
        TRUSTM_PROVIDER_DBGFN("TrustM crypt instance created. \n");
        

    }while(FALSE);      

    TRUSTM_PROVIDER_DBGFN("<");
    return return_status;
}


/**********************************************************************
* trustmProvider_App_Open_Recovery()
**********************************************************************/
optiga_lib_status_t trustmProvider_App_Open_Recovery(void)
{
    optiga_lib_status_t return_status;
    
    TRUSTM_PROVIDER_DBGFN(">");
      
    trustm_hibernate_flag = 0; 
    return_status = trustmProvider_App_Open();
    if (return_status != OPTIGA_LIB_SUCCESS) 
    { 
       TRUSTM_PROVIDER_DBGFN("Error opening Trust M, Retry 1");
      
       trustmProvider_App_Close();
       return_status = trustmProvider_App_Open();
       if (return_status != OPTIGA_LIB_SUCCESS)
       {
           TRUSTM_PROVIDER_ERRFN("Error opening Trust M, EXIT");
        }            
    }    
     
    TRUSTM_PROVIDER_DBGFN("<");
    return return_status;
}

/**********************************************************************
* trustmProvider_App_Open()
**********************************************************************/
optiga_lib_status_t trustmProvider_App_Open(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_PROVIDER_DBGFN(">");
    do
    {
       
        return_status = trustmProvider_Open();
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            TRUSTM_PROVIDER_ERRFN("Fail to create instances");
            break;
        }
        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */        
        if(*trustm_eng_mutex.pid==EMPTY_PID || *trustm_eng_mutex.pid != getpid() )
        {   
            TRUSTM_PROVIDER_DBGFN("optiga_util_open_application:Init");
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_open_application(me_util, 0);
            
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                TRUSTM_PROVIDER_ERRFN("Fail : optiga_util_open_application[1] \n");
                break;
            }
            //Wait until the optiga_util_open_application is completed
            return_status=trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            if (return_status != OPTIGA_LIB_SUCCESS)
            {   TRUSTM_PROVIDER_ERRFN("Fail : optiga_util_open_application time out[1] \n");
                trustmPrintErrorCode(return_status);
                break;
            }
            *trustm_eng_mutex.pid = getpid(); 
        }
        
        
        TRUSTM_PROVIDER_DBGFN("Success : optiga_util_open_application \n");
    }while(FALSE);      

    TRUSTM_PROVIDER_DBGFN("<");
    return return_status;
}



/**********************************************************************
* trustmProvider_Close()
**********************************************************************/
optiga_lib_status_t trustmProvider_Close(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_PROVIDER_DBGFN(">");

    // destroy util and crypt instances
    if (me_crypt!=NULL)
    {
        TRUSTM_PROVIDER_DBGFN("optiga_crypt_destroy\n");
        return_status = optiga_crypt_destroy(me_crypt);
        if(OPTIGA_LIB_SUCCESS != return_status)
        {
        TRUSTM_PROVIDER_ERRFN("Fail : optiga_crypt_destroy \n");
        }
    }

    if (me_util != NULL)
    {   TRUSTM_PROVIDER_DBGFN("optiga_util_destroy\n");
        return_status=optiga_util_destroy(me_util);   
    }
    //~ TRUSTM_WORKAROUND_TIMER_DISARM;

    // No point deinit the GPIO as it is a fix pin
    //pal_gpio_deinit(&optiga_reset_0);
    //pal_gpio_deinit(&optiga_vdd_0);
    me_util=NULL;
    me_crypt=NULL;    
    TRUSTM_PROVIDER_DBGFN("TrustM instance destroyed.\n");
    TRUSTM_PROVIDER_DBGFN("<");
    return return_status;
}

/**********************************************************************
* trustmProvider_App_Close()
**********************************************************************/
optiga_lib_status_t trustmProvider_App_Close(void)
{
    optiga_lib_status_t return_status;
    

    TRUSTM_HELPER_DBGFN(">");

    do{

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(me_util, 0);
            
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_close_application \n");
            break;
        }

        return_status=trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_PROVIDER_ERRFN("Fail : optiga_util_close_application time out \n");
            break;
        }
        TRUSTM_PROVIDER_DBGFN("Success : optiga_util_close_application \n");

    }while(FALSE);

    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);
    trustmProvider_Close();
    
    *trustm_eng_mutex.pid=EMPTY_PID;
    trustm_ipc_release(&trustm_eng_mutex);
    TRUSTM_PROVIDER_DBGFN("<");
    return return_status;
}


/**********************************************************************
* trustmProvider_App_Release()
**********************************************************************/
void trustmProvider_App_Release(void)
{
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_WORKAROUND_TIMER_DISARM;
    trustm_ipc_release(&trustm_eng_mutex);
    TRUSTM_PROVIDER_DBGFN("<");
      
}


void trustmProvider_SSLMutex_Acquire(void) 
{
    //TRUSTM_WORKAROUND_TIMER_ARM;
    trustm_ipc_acquire(&ssl_mutex, "/ssl-mutex");
}

void trustmProvider_SSLMutex_Release(void)
{
    //TRUSTM_WORKAROUND_TIMER_DISARM;
    trustm_ipc_release(&ssl_mutex);
}
///////////////////////////////////////////////////////////////////////////////////////////

#define TRUSTM_PROPS(op) ("provider=trustm,trustm." #op)

extern const OSSL_DISPATCH trustm_rand_functions[];

static const OSSL_ALGORITHM trustm_rands[] = {
    { "CTR-DRBG:0", "provider", trustm_rand_functions },
    { NULL, NULL, NULL }
};


extern const OSSL_DISPATCH trustm_digest_functions[];

static const OSSL_ALGORITHM trustm_digests[] = {
    { "SHA2-256:SHA-256:SHA256", "provider=trustm", trustm_digest_functions },
    { NULL, NULL, NULL }
};


extern const OSSL_DISPATCH trustm_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH trustm_ec_keymgmt_functions[];

// todo: add ec key management here too
static const OSSL_ALGORITHM trustm_keymgmts[] = {
    { "RSA:rsaEncryption", "provider=trustm", trustm_rsa_keymgmt_functions },
    { "EC:id-ecPublicKey", "provider=trustm", trustm_ec_keymgmt_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH trustm_ecdh_keyexch_functions[];

static const OSSL_ALGORITHM trustm_keyexchs[] = {
    { "ECDH", "provider=trustm", trustm_ecdh_keyexch_functions },
    { NULL, NULL, NULL }
}; 

extern const OSSL_DISPATCH trustm_rsa_encoder_text_functions[];
extern const OSSL_DISPATCH trustm_rsa_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH trustm_rsa_encoder_SubjectPublicKeyInfo_der_functions[];
extern const OSSL_DISPATCH trustm_rsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH trustm_rsa_encoder_pkcs1_pem_functions[];

extern const OSSL_DISPATCH trustm_ec_encoder_text_functions[];
extern const OSSL_DISPATCH trustm_ec_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH trustm_ec_encoder_SubjectPublicKeyInfo_der_functions[];

// dummy encoders
extern const OSSL_DISPATCH trustm_encoder_SubjectPrivateKeyInfo_pem_functions[];
extern const OSSL_DISPATCH trustm_encoder_SubjectPrivateKeyInfo_der_functions[];

// todo: add pem and der encoding format here too
static const OSSL_ALGORITHM trustm_encoders[] = {
    { "RSA", "provider=trustm,output=der,structure=pkcs1", trustm_rsa_encoder_pkcs1_der_functions },
    { "RSA", "provider=trustm,output=pem,structure=pkcs1", trustm_rsa_encoder_pkcs1_pem_functions },
    { "RSA", "provider=trustm,output=text", trustm_rsa_encoder_text_functions },
    { "RSA", "provider=trustm,output=der,structure=SubjectPublicKeyInfo", trustm_rsa_encoder_SubjectPublicKeyInfo_der_functions },
    { "RSA", "provider=trustm,output=pem,structure=SubjectPublicKeyInfo", trustm_rsa_encoder_SubjectPublicKeyInfo_pem_functions },
    { "EC", "provider=trustm,output=text", trustm_ec_encoder_text_functions },
    { "EC", "provider=trustm,output=der,structure=SubjectPublicKeyInfo", trustm_ec_encoder_SubjectPublicKeyInfo_der_functions },
    { "EC", "provider=trustm,output=pem,structure=SubjectPublicKeyInfo", trustm_ec_encoder_SubjectPublicKeyInfo_pem_functions },
    // dummy private key encoders
    { "RSA", "output=der,structure=SubjectPrivateKeyInfo", trustm_encoder_SubjectPrivateKeyInfo_der_functions },
    { "RSA", "output=pem,structure=SubjectPrivateKeyInfo", trustm_encoder_SubjectPrivateKeyInfo_pem_functions },
    { "EC", "output=der,structure=SubjectPrivateKeyInfo", trustm_encoder_SubjectPrivateKeyInfo_der_functions },
    { "EC", "output=pem,structure=SubjectPrivateKeyInfo",  trustm_encoder_SubjectPrivateKeyInfo_pem_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH trustm_object_store_functions[];

static const OSSL_ALGORITHM trustm_stores[] = {
    { "0xE0FC", TRUSTM_PROPS(store), trustm_object_store_functions },
    { "0xE0FD", TRUSTM_PROPS(store), trustm_object_store_functions },
    { "0xE0F0", TRUSTM_PROPS(store), trustm_object_store_functions },
    { "0xE0F1", TRUSTM_PROPS(store), trustm_object_store_functions },
    { "0xE0F2", TRUSTM_PROPS(store), trustm_object_store_functions },
    { "0xE0F3", TRUSTM_PROPS(store), trustm_object_store_functions },
    { NULL, NULL, NULL }
};


extern const OSSL_DISPATCH trustm_rsa_signature_functions[];
extern const OSSL_DISPATCH trustm_ecdsa_signature_functions[];

static const OSSL_ALGORITHM trustm_signatures[] = {
    { "RSA:rsaEncryption", "provider=trustm", trustm_rsa_signature_functions },
    { "ECDSA", "provider=trustm", trustm_ecdsa_signature_functions },
    { NULL, NULL, NULL }
};


extern const OSSL_DISPATCH trustm_rsa_asymcipher_functions[];

static const OSSL_ALGORITHM trustm_asymciphers[] = {
    { "RSA:rsaEncryption", "provider=trustm", trustm_rsa_asymcipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *trustm_query_operation(void *provctx, int operation_id, int *no_cache) 
{
    *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_RAND:
            return trustm_rands;

        case OSSL_OP_DIGEST:
            return trustm_digests;

        case OSSL_OP_KEYMGMT:
            return trustm_keymgmts;

        case OSSL_OP_ENCODER:
            return trustm_encoders;

        case OSSL_OP_STORE:
            return trustm_stores;

        case OSSL_OP_SIGNATURE:
            return trustm_signatures;

        case OSSL_OP_ASYM_CIPHER:
            return trustm_asymciphers;
        
        case OSSL_OP_KEYEXCH:
            return trustm_keyexchs;
    }

    return NULL;
}


static const OSSL_PARAM * trustm_gettable_params(void * provctx) 
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN("name", OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN("version", OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN("build", OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    
    return param_types;
}


static int trustm_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    
    for (p = params; p->key != NULL; p++) 
    {
        if (strcasecmp(p->key, "name") == 0) {
            *(const void **)p->data = "OPTIGA Trust M";
        }
        
        else if (strcasecmp(p->key, "version") == 0) {
            *(const void **)p->data = "1.0";
        }
        
        if (strcasecmp(p->key, "build") == 0) {
            *(const void **)p->data = "abc";
        }
    }

    return 1;
}



static void trustm_teardown(void *provctx) 
{
    trustm_ctx_t * trustm_ctx = provctx;
    
    TRUSTM_PROVIDER_DBGFN("> Provider destroy");
    trustm_ipc_acquire(&ssl_mutex, "/ssl-mutex");
    
    trustm_ctx->me_crypt = NULL;
    
    trustmProvider_Close();
    
    trustm_ipc_release(&ssl_mutex);
    TRUSTM_PROVIDER_DBGFN("<");
    
    OSSL_LIB_CTX_free(trustm_ctx->libctx);
    OPENSSL_clear_free(trustm_ctx, sizeof(trustm_ctx_t));
}

// todo: expand this list as more functions get implemented
static const OSSL_ITEM * trustm_get_reason_strings(void *provctx) 
{
    static const OSSL_ITEM reason_strings[] = {
        {TRUSTM_ERR_INIT_FAILURE, "TrustM Error Initializtion Failed"},
        {TRUSTM_ERR_CANNOT_GET_RANDOM, "TrustM Error cannot get random"},
        {0, NULL}
    };
    
    return reason_strings;
}


// todo: expand this list as more functions get implemented
static const OSSL_DISPATCH trustm_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*) (void))trustm_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*) (void))trustm_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*) (void))trustm_query_operation },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) trustm_teardown },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void)) trustm_get_reason_strings},
    { 0, NULL }
};


OPENSSL_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) 
{
    trustm_ctx_t *trustm_ctx = OPENSSL_zalloc(sizeof(trustm_ctx_t));
    
    
    if (trustm_ctx == NULL)
    {
        return 0;
    }
    
    trustm_ctx->core = handle;
    // init core functions
    init_core_func_from_dispatch(in);
    if ((trustm_ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in)) == NULL) {
        OSSL_LIB_CTX_free(trustm_ctx->libctx);
        OPENSSL_clear_free(trustm_ctx, sizeof(trustm_ctx_t));
        return 0;
    }
    
    
    // Init trust m chip
    trustm_ipc_acquire(&ssl_mutex, "/ssl-mutex");
    do {
        me_util = NULL;
        me_crypt = NULL;
        
        pal_gpio_init(&optiga_reset_0);
        pal_gpio_init(&optiga_vdd_0);
    } while (FALSE);
    trustm_ipc_release(&ssl_mutex);
    
    *provctx = trustm_ctx;
    *out = trustm_dispatch_table;
    
    return 1;
    //
}

