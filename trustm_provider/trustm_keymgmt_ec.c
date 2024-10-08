#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_ec_key_helper.h"

typedef struct trustm_ec_gen_ctx_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    optiga_key_id_t private_key_id;

    optiga_ecc_curve_t key_curve;
    optiga_key_usage_t key_usage;
} trustm_ec_gen_ctx_t;

static OSSL_FUNC_keymgmt_new_fn trustm_ec_keymgmt_new;
static OSSL_FUNC_keymgmt_gen_init_fn trustm_ec_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn trustm_ec_keymgmt_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn trustm_ec_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn trustm_ec_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn trustm_ec_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn trustm_ec_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn trustm_ec_keymgmt_load;
static OSSL_FUNC_keymgmt_free_fn trustm_ec_keymgmt_free;
static OSSL_FUNC_keymgmt_get_params_fn trustm_ec_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn trustm_ec_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn trustm_ec_keymgmt_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn trustm_ec_keymgmt_settable_params;
static OSSL_FUNC_keymgmt_has_fn trustm_ec_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn trustm_ec_keymgmt_match;
static OSSL_FUNC_keymgmt_import_fn trustm_ec_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn trustm_ec_keymgmt_eximport_types;
OSSL_FUNC_keymgmt_export_fn trustm_ec_keymgmt_export;


static void *trustm_ec_keymgmt_new(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_ec_key_t *trustm_ec_key = OPENSSL_zalloc(sizeof(trustm_ec_key_t));

    if (trustm_ec_key == NULL)
        return NULL;

    trustm_ec_key->core = trustm_ctx->core;
    trustm_ec_key->me_crypt = trustm_ctx->me_crypt;
    trustm_ec_key->me_util = trustm_ctx->me_util;

    // default EC key oid parameters
    trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_NIST_P_256;
    trustm_ec_key->key_usage = OPTIGA_KEY_USAGE_AUTHENTICATION;
    trustm_ec_key->public_key_length = sizeof(trustm_ec_key->public_key);

    trustm_ec_key->point_x_buffer_length = 0;
    trustm_ec_key->point_y_buffer_length = 0;

    trustm_ec_key->point_x_buffer_length = 0;
    trustm_ec_key->point_y_buffer_length = 0;

    return trustm_ec_key;
}

static void *trustm_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = OPENSSL_zalloc(sizeof(trustm_ec_gen_ctx_t));

    if (trustm_ec_gen_ctx == NULL)
        return NULL;

    trustm_ec_gen_ctx->core = trustm_ctx->core;
    trustm_ec_gen_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_ec_gen_ctx->me_util = trustm_ctx->me_util;

    if (trustm_ec_keymgmt_gen_set_params(trustm_ec_gen_ctx, params))
        return trustm_ec_gen_ctx;

    OPENSSL_clear_free(trustm_ec_gen_ctx, sizeof(trustm_ec_gen_ctx_t));
    return NULL;
}


static int trustm_ec_keymgmt_gen_set_template(void *ctx, void *temp1)
{
    trustm_ec_gen_ctx_t *gen = ctx;
    trustm_ec_key_t *pkey = temp1;

    gen->key_curve = pkey->key_curve;


    return 1;
}


static int trustm_ec_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, TRUSTM_PRIVATE_EC_KEY_OID);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &(trustm_ec_gen_ctx->private_key_id)))
        return 0;

    if ((trustm_ec_gen_ctx->private_key_id < 0xE0F0) || (trustm_ec_gen_ctx->private_key_id > 0xE0F3))
    {
        printf("Invalid EC Key OID %.4X\n", trustm_ec_gen_ctx->private_key_id);
        return 0;
    }


    p = OSSL_PARAM_locate_const(params, TRUSTM_KEY_USAGE);
    if (p != NULL && !OSSL_PARAM_get_int(p, (int *)&trustm_ec_gen_ctx->key_usage))
        return 0;
    
    //printf("EC Key Usage : %d\n", trustm_ec_gen_ctx->key_usage);


    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (strcasecmp("P-256", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_256;
        
        else if (strcasecmp("P-384", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_384;

        else if (strcasecmp("P-521", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_521;
        
        else if (strcasecmp("brainpoolP256r1", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;

        else if (strcasecmp("brainpoolP384r1", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;

        else if (strcasecmp("brainpoolP512r1", p->data) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
        
        else 
        {
            printf("Invalid EC key curve\n");
            return 0;
        }
    }

    //printf("Key curve : %.2X\n", trustm_ec_gen_ctx->key_curve);

    return 1;
}

static const OSSL_PARAM *trustm_ec_keymgmt_gen_settable_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(TRUSTM_PRIVATE_EC_KEY_OID, NULL),
        OSSL_PARAM_int(TRUSTM_KEY_USAGE, NULL),
        /* mandatory openssl param */
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *trustm_ec_keymgmt_gen(void *ctx, OSSL_CALLBACK *cb, void *cbarg)
{
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = ctx;
    trustm_ec_key_t *trustm_ec_key;
    optiga_lib_status_t return_status;
    int i = 0;


    // header templates
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
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.7
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07};

    uint8_t eccheaderBrainPool384[] = {0x30,0x7A, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.11
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B};  

    uint8_t eccheaderBrainPool512[] = {0x30,0x81,0x9B, // SEQUENCE
                                0x30,0x14, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x09, // OID:1.3.36.3.3.2.8.1.1.13
                                0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d}; 


    trustm_ec_key = OPENSSL_zalloc(sizeof(trustm_ec_key_t));
    if (trustm_ec_key == NULL)
        return NULL;

    trustm_ec_key->core = trustm_ec_gen_ctx->core;
    trustm_ec_key->me_crypt = trustm_ec_gen_ctx->me_crypt;
    trustm_ec_key->me_util = trustm_ec_gen_ctx->me_util;

    // transfer ec key parameters
    trustm_ec_key->private_key_id = trustm_ec_gen_ctx->private_key_id;
    trustm_ec_key->key_curve = trustm_ec_gen_ctx->key_curve;
    trustm_ec_key->key_usage = trustm_ec_gen_ctx->key_usage;
    trustm_ec_key->public_key_length = sizeof(trustm_ec_key->public_key);

    printf("Key OID : 0x%.4X\nKey curve 0x%.2X\nKey usage 0x%.2X\n", trustm_ec_key->private_key_id, trustm_ec_key->key_curve, trustm_ec_key->key_usage);

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_ec_key->me_crypt = me_crypt;
    trustm_ec_key->me_util = me_util;

    switch (trustm_ec_key->key_curve)
    {
        case OPTIGA_ECC_CURVE_NIST_P_256:
        trustm_ec_key->public_key_header_length = sizeof(eccheader256);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheader256[i];
        
        break;

        case OPTIGA_ECC_CURVE_NIST_P_384:
        trustm_ec_key->public_key_header_length = sizeof(eccheader384);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheader384[i];
        
        break;

        case OPTIGA_ECC_CURVE_NIST_P_521:
        trustm_ec_key->public_key_header_length = sizeof(eccheader521);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheader521[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        trustm_ec_key->public_key_header_length = sizeof(eccheaderBrainPool256);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheaderBrainPool256[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        trustm_ec_key->public_key_header_length = sizeof(eccheaderBrainPool384);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheaderBrainPool384[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
        trustm_ec_key->public_key_header_length = sizeof(eccheaderBrainPool512);

        for (i = 0; i < trustm_ec_key->public_key_header_length; i++)
            trustm_ec_key->public_key[i] = eccheaderBrainPool512[i];
        
        break;
    }

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecc_generate_keypair(trustm_ec_key->me_crypt,
                                                    trustm_ec_key->key_curve,
                                                    trustm_ec_key->key_usage,
                                                    FALSE,
                                                    &(trustm_ec_key->private_key_id),
                                                    ((trustm_ec_key->public_key)+i),
                                                    &(trustm_ec_key->public_key_length));

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        printf("Error in EC key generation1\nError code : 0x%.4X\n", return_status);
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Error in EC key generation\nError code : 0x%.4X\n", return_status);
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    } 

    uint16_t public_id = ((trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)) ?
                                (trustm_ec_key->private_key_id + 0x10EF) : (trustm_ec_key->private_key_id + 0x10E0);
    
    printf("Saving public EC key to OID : 0x%.4X ...\n", public_id);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_write_data(trustm_ec_gen_ctx->me_util, 
                                        public_id, 
                                        OPTIGA_UTIL_ERASE_AND_WRITE,
                                        0,
                                        trustm_ec_key->public_key,
                                        trustm_ec_key->public_key_length+i);

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        printf("Error in EC public key save\nError code : 0x%.4X\n", return_status);
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Error in EC public key save\nError code : 0x%.4X\n", return_status);
    }                    

    // update public key length and public key header length
    trustm_ec_key->public_key_length += i;
    trustm_ec_key->public_key_header_length = i;

    // extracting ecc points
    if (trustm_ecc_public_key_to_point(trustm_ec_key) == 0)
    
    {
        printf("Error in EC key converting to coordinate points\n");
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    return trustm_ec_key;
}

static void trustm_ec_keymgmt_gen_cleanup(void *ctx)
{
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = ctx;

    if (trustm_ec_gen_ctx == NULL)
        return;

    OPENSSL_clear_free(trustm_ec_gen_ctx, sizeof(trustm_ec_gen_ctx_t));
}

static void *trustm_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
    trustm_ec_key_t *trustm_ec_key = NULL;

    if (!reference || reference_sz != sizeof(trustm_ec_key))
        return NULL;

    trustm_ec_key = *(trustm_ec_key_t **)reference;
    *(trustm_ec_key_t **)reference = NULL;

    return trustm_ec_key;
}

static void trustm_ec_keymgmt_free(void *keydata)
{
    trustm_ec_key_t *trustm_ec_key = keydata;

    if (trustm_ec_key == NULL)
        return;

    OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
}



static int trustm_ec_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    trustm_ec_key_t *trustm_ec_key =(trustm_ec_key_t *) keydata;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, OBJ_nid2sn(trustm_ecc_curve_to_nid(trustm_ec_key->key_curve))))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL)
    {
        int sec_bits;

        if (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1 
            || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521)
            sec_bits = 256;

        else if (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1 
            || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_384)
            sec_bits = 192;

        else
            sec_bits = 128;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            return 0;
    }

    /* public key */
    // getting uncompressed format
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) 
    {
        size_t size;
        void *buffer;
        
        size = trustm_ec_point_to_uncompressed_buffer(trustm_ec_key, &buffer);
        if (size == 0)
            return 0;
            
        if (OSSL_PARAM_set_octet_string(p, buffer, size) == 0)
            return 0;
        OPENSSL_free(buffer);
    }
    
    // x point
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
    if (p != NULL) 
    {
        if (trustm_ec_key->point_x_buffer_length == 0)
            return 0;
            
        BIGNUM *bignum = BN_bin2bn(trustm_ec_key->x, trustm_ec_key->point_x_buffer_length, NULL);
        if (OSSL_PARAM_set_BN(p, bignum) == 0)
            return 0;
            
        BN_free(bignum);
    }
    
    // y point 
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
    if (p != NULL) 
    {
        if (trustm_ec_key->point_y_buffer_length == 0)
            return 0;
            
        BIGNUM *bignum = BN_bin2bn(trustm_ec_key->y, trustm_ec_key->point_y_buffer_length, NULL);
        if (OSSL_PARAM_set_BN(p, bignum) == 0)
            return 0;
            
        BN_free(bignum);
    }
    
    return 1;
}

static const OSSL_PARAM *trustm_ec_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        
        /* public key */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };
    
    return gettable;
}

static int trustm_ec_keymgmt_set_params(void *keydata, const OSSL_PARAM params[]) 
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *) keydata;
    const OSSL_PARAM *p;
    
    if (params == NULL)
        return 1;
        
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        
        if (trustm_buffer_to_ecc_point(trustm_ec_key, p->data, p->data_size) == 0)
            return 0;
    }
    
    return 1;
}

static const OSSL_PARAM *trustm_ec_keymgmt_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    
    return settable;
}

static const char *trustm_ec_keymgmt_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }

    return NULL;
}

#define EC_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

static int trustm_ec_keymgmt_has(const void *keydata, int selection)
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *)keydata;
    int res = 1;

    if (trustm_ec_key == NULL)
        return 0;

    if ((selection & EC_POSSIBLE_SELECTIONS) == 0)
        return 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0))
        res = res && (trustm_ec_key->point_x_buffer_length > 0) && (trustm_ec_key->point_y_buffer_length > 0);
    
    return res;
}

static int trustm_ec_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    trustm_ec_key_t *pkey1 = (trustm_ec_key_t *)keydata1;
    trustm_ec_key_t *pkey2 = (trustm_ec_key_t *)keydata2;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) 
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            // compare curve
            if (pkey1->key_curve != pkey2->key_curve)
                return 0;
            
            // compare point
            if ((pkey1->point_x_buffer_length != pkey2->point_x_buffer_length) 
                && (memcmp(pkey1->x, pkey2->x, pkey1->point_x_buffer_length) != 0))
                return 0;
            
            if ((pkey1->point_y_buffer_length != pkey2->point_y_buffer_length) 
                && (memcmp(pkey1->y, pkey2->y, pkey1->point_y_buffer_length) != 0))
                return 0;
        }

        else 
            return 0; // cannot compare private keys
    }

    return 1;
}

static int trustm_ec_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *)keydata;
    const OSSL_PARAM *p;

    if (trustm_ec_key == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) 
        {
            if (p->data_type != OSSL_PARAM_UTF8_STRING)
                return 0;

            int nid;
            nid = EC_curve_nist2nid(p->data);
            
            if (nid == NID_undef)
                nid = OBJ_sn2nid(p->data);

            if (nid == NID_undef)
                return 0;

            trustm_ec_key->key_curve = trustm_nid_to_ecc_curve(nid);
            if (trustm_ec_key->key_curve == 0)
            {
                printf("Unknown key curve from import\n");
                return 0;
            }          
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL)
        {
            if (trustm_buffer_to_ecc_point(trustm_ec_key, p->data, p->data_size) == 0)
                return 0;
        }
    }

    return 1;
}

int trustm_ec_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *)keydata;
    int curve_nid;
    int res = 0;

    void *pubbuff = NULL;
    size_t pubsize;

    if (trustm_ec_key == NULL || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 0;

    curve_nid = trustm_ecc_curve_to_nid(trustm_ec_key->key_curve);

    pubsize = trustm_ec_point_to_uncompressed_buffer(trustm_ec_key, &pubbuff);
    if (pubsize == 0)
        return 0;

    OSSL_PARAM params[3];
    OSSL_PARAM *p = params;

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)OBJ_nid2sn(curve_nid), 0);

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubbuff, pubsize);

    *p = OSSL_PARAM_construct_end();

    res = param_cb(params, cbarg);
    OPENSSL_free(pubbuff);
    return res;
}

static const OSSL_PARAM *trustm_ec_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return ecc_public_key_types;
    
    return NULL;
}

const OSSL_DISPATCH trustm_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void(*)(void))trustm_ec_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void(*)(void))trustm_ec_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void(*)(void))trustm_ec_keymgmt_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void(*)(void))trustm_ec_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void(*)(void))trustm_ec_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void(*)(void))trustm_ec_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void(*)(void))trustm_ec_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void(*)(void))trustm_ec_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void(*)(void))trustm_ec_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))trustm_ec_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))trustm_ec_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void(*)(void))trustm_ec_keymgmt_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void(*)(void))trustm_ec_keymgmt_settable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void(*)(void))trustm_ec_keymgmt_query_operation_name },
    { OSSL_FUNC_KEYMGMT_HAS, (void(*)(void))trustm_ec_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))trustm_ec_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void(*)(void))trustm_ec_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void(*)(void))trustm_ec_keymgmt_eximport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void(*)(void))trustm_ec_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void(*)(void))trustm_ec_keymgmt_eximport_types },
    { 0, NULL }  
};
