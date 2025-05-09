#include <string.h>
#include <math.h>


#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "trustm_helper.h"
#include "trustm_provider_common.h"

#define PUBLIC_KEY_LEN  1024



typedef struct trustm_rsa_gen_ctx_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    // private key oids
    optiga_key_id_t private_key_id;

    // optiga trustm's side variables
    optiga_rsa_key_type_t key_size;
    optiga_key_usage_t key_usage;

    uint32_t exponent;

} trustm_rsa_gen_ctx_t;

static OSSL_FUNC_keymgmt_new_fn trustm_rsa_keymgmt_new;
static OSSL_FUNC_keymgmt_gen_init_fn trustm_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn trustm_rsa_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn trustm_rsa_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn trustm_rsa_keymgmt_gen;
static OSSL_FUNC_keymgmt_load_fn trustm_rsa_keymgmt_load;
static OSSL_FUNC_keymgmt_free_fn trustm_rsa_keymgmt_free;
static OSSL_FUNC_keymgmt_get_params_fn trustm_rsa_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn trustm_rsa_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_query_operation_name_fn trustm_rsa_keymgmt_query_operation_name;
static OSSL_FUNC_keymgmt_has_fn trustm_rsa_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn trustm_rsa_keymgmt_match;
static OSSL_FUNC_keymgmt_import_fn trustm_rsa_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn trustm_rsa_keymgmt_eximport_types;
OSSL_FUNC_keymgmt_export_fn trustm_rsa_keymgmt_export;



static void *trustm_rsa_keymgmt_new(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_rsa_key_t *trustm_rsa_key = OPENSSL_zalloc(sizeof(trustm_rsa_key_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_key == NULL)
    {
        return NULL;
    }

    trustm_rsa_key->core = trustm_ctx->core;
    trustm_rsa_key->me_crypt = trustm_ctx->me_crypt;
    trustm_rsa_key->me_util  = trustm_ctx->me_util;

    // default values
    trustm_rsa_key->key_size = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
    trustm_rsa_key->key_usage = OPTIGA_KEY_USAGE_AUTHENTICATION;

    // init public key array here
    trustm_rsa_key->public_key_length = 0;
    trustm_rsa_key->modulus_length = sizeof(trustm_rsa_key->modulus);

    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_rsa_key;
}

static void *trustm_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_rsa_gen_ctx_t *trustm_rsa_gen_ctx = OPENSSL_zalloc(sizeof(trustm_rsa_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_gen_ctx == NULL)
    {
        return NULL;
    }

    trustm_rsa_gen_ctx->core = trustm_ctx->core;
    trustm_rsa_gen_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_rsa_gen_ctx->me_util = trustm_ctx->me_util;
    

    // init rsa key params from OSSL_PARAMS
    if (trustm_rsa_keymgmt_gen_set_params(trustm_rsa_gen_ctx, params))
        return trustm_rsa_gen_ctx;

    OPENSSL_clear_free(trustm_rsa_gen_ctx, sizeof(trustm_rsa_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<");
    return NULL;
}

static int trustm_rsa_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_rsa_gen_ctx_t *trustm_rsa_gen_ctx = ctx;
    const OSSL_PARAM *p;
    size_t primes, bits;
    BIGNUM *e = NULL;
    TRUSTM_PROVIDER_DBGFN(">");
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, TRUSTM_PRIVATE_RSA_KEY_OID);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &trustm_rsa_gen_ctx->private_key_id))
        return 0;

    // check if valid RSA OID provided
    if (trustm_rsa_gen_ctx->private_key_id < 0xE0FC || trustm_rsa_gen_ctx->private_key_id > 0xE0FD) 
    {
        TRUSTM_PROVIDER_ERRFN("Invalid RSA key OID %.4X\n", trustm_rsa_gen_ctx->private_key_id);
        return 0;
    }
    
    p = OSSL_PARAM_locate_const(params, TRUSTM_KEY_USAGE);
    if (p != NULL && !OSSL_PARAM_get_int(p, (int *)&trustm_rsa_gen_ctx->key_usage))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_size_t(p, &bits))
            return 0;

        // manually set key length parameter
        if (bits == 1024)
            trustm_rsa_gen_ctx->key_size = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
    
        else if (bits == 2048)
            trustm_rsa_gen_ctx->key_size = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;

        else 
        {
            TRUSTM_PROVIDER_ERRFN("Invalid RSA key length %d\n", bits);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &primes) || primes != 2))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_get_BN(p, &e))
            return 0;

        trustm_rsa_gen_ctx->exponent = BN_get_word(e);
        BN_free(e);
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static const OSSL_PARAM * trustm_rsa_keymgmt_gen_settable_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(TRUSTM_PRIVATE_RSA_KEY_OID, NULL),
        OSSL_PARAM_int(TRUSTM_KEY_USAGE, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *trustm_rsa_keymgmt_gen(void *ctx, OSSL_CALLBACK *cb, void *cbarg)
{
    trustm_rsa_gen_ctx_t *trustm_rsa_gen_ctx = ctx;
    trustm_rsa_key_t *trustm_rsa_key = NULL;
    int i;
    optiga_lib_status_t return_status;

    uint8_t rsaheader2048[] = {0x30, 0x82, 0x01, 0x22,
                                0x30, 0x0d,
                                0x06, 0x09,
                                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                                0x05, 0x00};

    uint8_t rsaheader1024[] = {0x30, 0x81, 0x9f,
                                0x30, 0x0d,
                                0x06, 0x09, 
                                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                                0x05, 0x00};

    trustm_rsa_key = OPENSSL_zalloc(sizeof(trustm_rsa_key_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_key == NULL)
    {
        // add error raise here
        return NULL;
    }

    trustm_rsa_key->core = trustm_rsa_gen_ctx->core;
    trustm_rsa_key->me_crypt = trustm_rsa_gen_ctx->me_crypt;
    trustm_rsa_key->me_util = trustm_rsa_gen_ctx->me_util;
    trustm_rsa_key->private_key_id = trustm_rsa_gen_ctx->private_key_id;
    trustm_rsa_key->key_size = trustm_rsa_gen_ctx->key_size;
    trustm_rsa_key->key_usage = trustm_rsa_gen_ctx->key_usage;
    trustm_rsa_key->public_key_length = sizeof(trustm_rsa_key->public_key);
    trustm_rsa_key->exponent = trustm_rsa_gen_ctx->exponent;
    

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_rsa_key->me_crypt = me_crypt;
    trustm_rsa_key->me_util = me_util;

    if (trustm_rsa_key->key_size == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL) 
    {
        trustm_rsa_key->public_key_header_length = sizeof(rsaheader2048);
        for (i = 0; i < trustm_rsa_key->public_key_header_length; i++)
        {
            trustm_rsa_key->public_key[i] = rsaheader2048[i];
        }
    }
    
    else 
    {
        trustm_rsa_key->public_key_header_length = sizeof(rsaheader1024);
        for (i = 0; i < trustm_rsa_key->public_key_header_length; i++)
        {
            trustm_rsa_key->public_key[i] = rsaheader1024[i];
        }
    }


    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_generate_keypair(trustm_rsa_key->me_crypt, 
                                                        trustm_rsa_key->key_size,
                                                        trustm_rsa_key->key_usage,
                                                        FALSE,
                                                        &(trustm_rsa_key->private_key_id),
                                                        (trustm_rsa_key->public_key+i),
                                                        &(trustm_rsa_key->public_key_length));
    
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_rsa_generate_keypair\nError code : 0x%.4X\n", return_status);
        OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
        return NULL;
    }

    // wait until the optiga_crypt_rsa_generate_keypair operation is completed
    printf("Generating RSA keypair using TrustM....\n");
    trustmProvider_WaitForCompletion(MAX_RSA_KEY_GEN_TIME); // can take up to 60s
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error generating RSA key pair. Return status: %d\n", return_status);
        OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
        return NULL;
    }

    // saving public key to private_key_id+0x10E4
    printf("Writing public key to OID 0x%.4X\n", (trustm_rsa_key->private_key_id)+0x10E4);
    trustm_util_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_write_data(trustm_rsa_key->me_util,
                                            (trustm_rsa_key->private_key_id)+0x10E4,
                                            OPTIGA_UTIL_ERASE_AND_WRITE,
                                            0,
                                            trustm_rsa_key->public_key,
                                            trustm_rsa_key->public_key_length + i);

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
        return NULL;
    }

    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT); 
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
        return NULL;
    }

    trustm_rsa_key->public_key_length += i;

    printf("Writing public key to OID 0x%.4X  SUCCESS\n", (trustm_rsa_key->private_key_id)+0x10E4);

    // extracting modulus
    BIGNUM *nbig;
    uint8_t modulus_buffer[300];
    uint16_t modulus_length;

    /* extracting modulus from trustm rsa public key struct */
    if (trustm_rsa_key->key_size == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL)
    {
        modulus_length = trustm_rsa_key->public_key[trustm_rsa_key->public_key_header_length + 9]; // get the total length in bytes of modulus
        memcpy(modulus_buffer, (trustm_rsa_key->public_key + trustm_rsa_key->public_key_header_length + 10), modulus_length);
    }
    else 
    {
        modulus_length = (trustm_rsa_key->public_key[trustm_rsa_key->public_key_header_length + 11]) << 8 | 
                                    (trustm_rsa_key->public_key[trustm_rsa_key->public_key_header_length + 12]); // get the total length in bytes of modulus

        memcpy(modulus_buffer, (trustm_rsa_key->public_key + trustm_rsa_key->public_key_header_length + 13), modulus_length);
    }

    /* set n */
    nbig = BN_bin2bn(modulus_buffer, modulus_length, NULL);
    int tolen = BN_bn2bin(nbig, trustm_rsa_key->modulus);

    if (tolen < 0)
    {
        OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
        return NULL;
    }

    trustm_rsa_key->modulus_length = tolen;
    BN_free(nbig);

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_rsa_key;
}

static void trustm_rsa_keymgmt_gen_cleanup(void *ctx)
{
    trustm_rsa_gen_ctx_t *trustm_rsa_gen_ctx = ctx;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_gen_ctx == NULL)
        return;

    OPENSSL_clear_free(trustm_rsa_gen_ctx, sizeof(trustm_rsa_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<");
}

static void trustm_rsa_keymgmt_free(void *keydata)
{
    trustm_rsa_key_t *trustm_rsa_key = keydata;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_key == NULL)
        return;

    OPENSSL_clear_free(trustm_rsa_key, sizeof(trustm_rsa_key_t));
    TRUSTM_PROVIDER_DBGFN("<");
}

static int trustm_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    trustm_rsa_key_t *trustm_rsa_key = keydata;
    OSSL_PARAM *p;
    TRUSTM_PROVIDER_DBGFN(">");
    TRACE_PARAMS("Trust M rsa keymgmt get_params", params);
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        int size;
        if (trustm_rsa_key->key_size == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
            size = 2048;
        else 
            size = 1024;

        if (!OSSL_PARAM_set_int(p, size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, TRUSTM_KEY_USAGE);
    if (p != NULL && !OSSL_PARAM_set_int(p, trustm_rsa_key->key_usage))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (p != NULL)
    {
        BIGNUM *bignum = BN_bin2bn(trustm_rsa_key->modulus, trustm_rsa_key->modulus_length, NULL);
        if (!OSSL_PARAM_set_BN(p, bignum))
        {
            BN_free(bignum);
            return 0;
        }
        BN_free(bignum);
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL)
    {
        BIGNUM *bignum = BN_new();

        BN_set_word(bignum, trustm_rsa_key->exponent);
        if (!OSSL_PARAM_set_BN(p, bignum))
        {
            BN_free(bignum);
            return 0;
        }
        BN_free(bignum);
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static const OSSL_PARAM * trustm_rsa_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(TRUSTM_KEY_USAGE, NULL),
        /* public key */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    
    return gettable;
}

static const char *trustm_rsa_keymgmt_query_operation_name(int operation_id)
{
    return "RSA";
}



#define RSA_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
static int trustm_rsa_keymgmt_has(const void *keydata, int selection)
{
    const trustm_rsa_key_t *trustm_rsa_key = keydata;
    int res = 1;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_key == NULL)
        return 0;

    
    if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
        return 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0))
        res = res && (trustm_rsa_key->public_key_length > 0);
    TRUSTM_PROVIDER_DBGFN("<");
    return res; 
}

static void *trustm_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    trustm_rsa_key_t *trustm_rsa_key = NULL;
    TRUSTM_PROVIDER_DBGFN(">");
    if (!reference || reference_sz != sizeof(trustm_rsa_key))
        return NULL;
    
    trustm_rsa_key = *(trustm_rsa_key_t **) reference;
    *(trustm_rsa_key_t **)reference = NULL;
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_rsa_key;
}

static int trustm_rsa_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    trustm_rsa_key_t *rsa_key1 = (trustm_rsa_key_t *)keydata1;
    trustm_rsa_key_t *rsa_key2 = (trustm_rsa_key_t *)keydata2;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            if (rsa_key1->modulus_length != rsa_key2->modulus_length)
            {
                return 0;
            }

            if (memcmp(rsa_key1->modulus, rsa_key2->modulus, rsa_key1->modulus_length) != 0)
                return 0;
        }

        else 
            return 0;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

int trustm_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    trustm_rsa_key_t *trustm_rsa_key = keydata;
    uint32_t exponent;
    int ok = 1;

    OSSL_PARAM params[10];
    OSSL_PARAM *p = params;
    uint8_t priv_exponent[1] = {0x00};         
    uint8_t prime1[1]        = {0x01};         
    uint8_t prime2[4]        = {0x00, 0x00, 0x00, 0x00};  // Dummy q (embed keyID here)
    uint8_t exponent1[1]     = {0x00};         
    uint8_t exponent2[1]     = {0x00};         
    uint8_t coefficient[4]   = {0x00, 0x00, 0x00, 0x00};  
    
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_rsa_key == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) 
    {
        unsigned char *reversed_modulus = malloc(trustm_rsa_key->modulus_length);
        if (reversed_modulus) {
            for (size_t i = 0; i < trustm_rsa_key->modulus_length; i++) {
                reversed_modulus[i] = trustm_rsa_key->modulus[trustm_rsa_key->modulus_length - 1 - i];
            }
            *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                   reversed_modulus,
                                   trustm_rsa_key->modulus_length);
         }                                                                                               
        exponent = 0x10001;
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (unsigned char*)&exponent, sizeof(exponent));
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        TRUSTM_PROVIDER_DBGFN("Exporting dummy private key components with keyID embedded:");
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, priv_exponent, sizeof(priv_exponent));
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, prime1, sizeof(prime1));

        memcpy(prime2, &trustm_rsa_key->private_key_id, sizeof(trustm_rsa_key->private_key_id));
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, prime2, sizeof(prime2));
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, exponent1, sizeof(exponent1));
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, exponent2, sizeof(exponent2));
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, coefficient, sizeof(coefficient));

    }
    *p = OSSL_PARAM_construct_end();

    ok = param_cb(params, cbarg);
    TRUSTM_PROVIDER_DBGFN("<");
    return ok;
}

static int trustm_rsa_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    trustm_rsa_key_t *trustm_rsa_key = (trustm_rsa_key_t *)keydata;
    const OSSL_PARAM *p;
    size_t bits;
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_DBGFN("selection: %d (0x%X)", selection, selection); 
    if (trustm_rsa_key == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
        if (p != NULL)
        {
            BIGNUM *bignum = NULL;
            int tolen;

            if (!OSSL_PARAM_get_BN(p, &bignum))
                return 0;

            bits = BN_num_bits(bignum);

            // manually set key length parameter
            if (bits == 1024)
                trustm_rsa_key->key_size = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
    
            else if (bits == 2048)
                trustm_rsa_key->key_size = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
          
            tolen = BN_bn2bin(bignum, trustm_rsa_key->modulus);
            BN_free(bignum);

            if (tolen < 0) 
                return 0;

            trustm_rsa_key->modulus_length = tolen;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) 
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
        if (p != NULL) 
        {
            BIGNUM *bignum = NULL;
            uint8_t prime2[4] = {0};  
            int tolen;

            if (!OSSL_PARAM_get_BN(p, &bignum)) {
                TRUSTM_PROVIDER_DBGFN("Error: Failed to get prime2 from params");
                return 0;
            }

            tolen = BN_bn2bin(bignum, prime2);
            BN_free(bignum);

            if (tolen <= 0 || tolen > sizeof(prime2)) {
                TRUSTM_PROVIDER_DBGFN("Error: Invalid prime2 length (%d)", tolen);
                return 0;
            }
            // Extract private_key_id 
            trustm_rsa_key->private_key_id = (prime2[0] << 8) | prime2[1];
            TRUSTM_PROVIDER_DBGFN("Imported private_key_id: 0x%04x", trustm_rsa_key->private_key_id);
        } 
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static const OSSL_PARAM *trustm_rsa_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM rsa_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    TRUSTM_PROVIDER_DBGFN(">");
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return rsa_public_key_types;
    TRUSTM_PROVIDER_DBGFN("<");
    return NULL;
}

const OSSL_DISPATCH trustm_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void(*)(void))trustm_rsa_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void(*)(void))trustm_rsa_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void(*)(void))trustm_rsa_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void(*)(void))trustm_rsa_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void(*)(void))trustm_rsa_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void(*)(void))trustm_rsa_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void(*)(void))trustm_rsa_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void(*)(void))trustm_rsa_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))trustm_rsa_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))trustm_rsa_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void(*)(void))trustm_rsa_keymgmt_query_operation_name },
    { OSSL_FUNC_KEYMGMT_HAS, (void(*)(void))trustm_rsa_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))trustm_rsa_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void(*)(void))trustm_rsa_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void(*)(void))trustm_rsa_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void(*)(void))trustm_rsa_keymgmt_eximport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void(*)(void))trustm_rsa_keymgmt_eximport_types },
    {0, NULL}
};

