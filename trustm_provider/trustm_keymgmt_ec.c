#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_key_helper.h"
#define DEFAULT_EC_KEY_ID 0xE0F1

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
    TRUSTM_PROVIDER_DBGFN(">");
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

    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_ec_key;
}

static void *trustm_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = OPENSSL_zalloc(sizeof(trustm_ec_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_ec_gen_ctx == NULL)
        return NULL;

    trustm_ec_gen_ctx->core = trustm_ctx->core;
    trustm_ec_gen_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_ec_gen_ctx->me_util = trustm_ctx->me_util;

    if (trustm_ec_keymgmt_gen_set_params(trustm_ec_gen_ctx, params))
        return trustm_ec_gen_ctx;

    OPENSSL_clear_free(trustm_ec_gen_ctx, sizeof(trustm_ec_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<");
    return NULL;
}


static int trustm_ec_keymgmt_gen_set_template(void *ctx, void *temp1)
{
    trustm_ec_gen_ctx_t *gen = ctx;
    trustm_ec_key_t *pkey = temp1;
    TRUSTM_PROVIDER_DBGFN(">");
    gen->key_curve = pkey->key_curve;
    gen->private_key_id = pkey->private_key_id;

    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}


static int trustm_ec_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = ctx;
    const OSSL_PARAM *p;
    TRUSTM_PROVIDER_DBGFN(">");
    char grp_name[32] = {0}; 
    char *grp_name_tmp = grp_name;
    char *keyId_str     = NULL;
    if (params == NULL)
        return 1;
    const OSSL_PARAM *param_dbg = params;
    TRUSTM_PROVIDER_DBGFN("Received parameters:");
    while (param_dbg != NULL && param_dbg->key != NULL) {
        TRUSTM_PROVIDER_DBG("Param: %s", param_dbg->key);
        param_dbg++;
    }
    //~ p = OSSL_PARAM_locate_const(params, TRUSTM_PRIVATE_EC_KEY_OID);
    //~ if (p != NULL && !OSSL_PARAM_get_uint32(p, &(trustm_ec_gen_ctx->private_key_id)))
        //~ return 0;

    //~ if ((trustm_ec_gen_ctx->private_key_id < 0xE0F0) || (trustm_ec_gen_ctx->private_key_id > 0xE0F3))
    //~ {
        //~ TRUSTM_PROVIDER_ERRFN("Invalid EC Key OID %.4X\n", trustm_ec_gen_ctx->private_key_id);
        //~ return 0;
    //~ }
    //~ p = OSSL_PARAM_locate_const(params, TRUSTM_KEY_USAGE);
    //~ if (p != NULL && !OSSL_PARAM_get_int(p, (int *)&trustm_ec_gen_ctx->key_usage))
        //~ return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        TRUSTM_PROVIDER_DBG("Key Curve Param: %s", (char *)p->data);
        strncpy(grp_name, p->data, sizeof(grp_name) - 1);
        grp_name_tmp = strtok(grp_name, ":");  
        keyId_str = strtok(NULL, ":");  
        if (strcasecmp("prime256v1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_256;
        else if (strcasecmp("secp384r1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_384;
        else if (strcasecmp("secp521r1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_NIST_P_521;
        else if (strcasecmp("brainpoolP256r1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;
        else if (strcasecmp("brainpoolP384r1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;
        else if (strcasecmp("brainpoolP512r1", grp_name_tmp) == 0)
            trustm_ec_gen_ctx->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
        else {
            TRUSTM_PROVIDER_ERRFN("Invalid EC key curve: %s\n", grp_name_tmp);
            return 0;
        }

    }
    TRUSTM_PROVIDER_DBG("Key curve : %.2X\n", trustm_ec_gen_ctx->key_curve);
    TRUSTM_PROVIDER_DBG("Extracted Key ID String: %s\n", keyId_str ? keyId_str : "NULL");

    if (keyId_str == NULL) {
        TRUSTM_PROVIDER_MSGFN( "No key id found. Default id will be used \n");
        trustm_ec_gen_ctx->private_key_id = DEFAULT_EC_KEY_ID;
    }
    else {
        char *hex_start = keyId_str;
        errno = 0;
        uint32_t key_id;
        const char needle[3] = "0x";
        if (strncmp(keyId_str, needle, 2) == 0) {
        hex_start += 2; // Skip "0x"
        } else {
        TRUSTM_PROVIDER_ERRFN("Key ID does not start with '0x': %s\n", keyId_str);
        return 0; 
        }
        sscanf(hex_start, "%x", &key_id);
        trustm_ec_gen_ctx->private_key_id = key_id;
        if ((trustm_ec_gen_ctx->private_key_id < 0xE0F0) || (trustm_ec_gen_ctx->private_key_id > 0xE0F3))
        {
        TRUSTM_PROVIDER_ERRFN("Invalid EC Key OID: %.4X\n", trustm_ec_gen_ctx->private_key_id);
        return 0;
        }
        else {
        TRUSTM_PROVIDER_DBG("EC Key OID %.4X\n", trustm_ec_gen_ctx->private_key_id);
        return 1;
        }
    }
    TRUSTM_PROVIDER_DBGFN("<");
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
    TRUSTM_PROVIDER_DBGFN(">");

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
    //trustm_ec_key->key_usage = trustm_ec_gen_ctx->key_usage;
    trustm_ec_key->key_usage = 0x13;
    trustm_ec_key->public_key_length = sizeof(trustm_ec_key->public_key);

    TRUSTM_PROVIDER_DBG("Key OID : 0x%.4X\nKey curve 0x%.2X\nKey usage 0x%.2X\n", trustm_ec_key->private_key_id, trustm_ec_key->key_curve, trustm_ec_key->key_usage);

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

    trustm_crypt_ShieldedConnection();
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
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecc_generate_keypair\nError code : 0x%.4X\n", return_status);
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in EC key generation\nError code : 0x%.4X\n", return_status);
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    } 

    uint16_t public_id = ((trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)) ?
                                (trustm_ec_key->private_key_id + 0x10EF) : (trustm_ec_key->private_key_id + 0x10E0);
    
    printf("Saving public EC key to OID : 0x%.4X ...\n", public_id);

    trustm_util_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_write_data(trustm_ec_key->me_util, 
                                        public_id, 
                                        OPTIGA_UTIL_ERASE_AND_WRITE,
                                        0,
                                        trustm_ec_key->public_key,
                                        trustm_ec_key->public_key_length+i);

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_util_write_data\nError code : 0x%.4X\n", return_status);
        return 0;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in EC public key saving\nError code : 0x%.4X\n", return_status);
        return 0;
    }                    

    // update public key length and public key header length
    trustm_ec_key->public_key_length += i;
    trustm_ec_key->public_key_header_length = i;

    // extracting ecc points
    if (trustm_ecc_public_key_to_point(trustm_ec_key) == 0)
    
    {
        TRUSTM_PROVIDER_ERRFN("Error in EC key converting to coordinate points\n");
        OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return NULL;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_ec_key;
}

static void trustm_ec_keymgmt_gen_cleanup(void *ctx)
{
    trustm_ec_gen_ctx_t *trustm_ec_gen_ctx = ctx;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_ec_gen_ctx == NULL)
        return;

    OPENSSL_clear_free(trustm_ec_gen_ctx, sizeof(trustm_ec_gen_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<");
}

static void *trustm_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
    trustm_ec_key_t *trustm_ec_key = NULL;
    TRUSTM_PROVIDER_DBGFN(">");
    if (!reference || reference_sz != sizeof(trustm_ec_key))
        return NULL;

    trustm_ec_key = *(trustm_ec_key_t **)reference;
    *(trustm_ec_key_t **)reference = NULL;
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_ec_key;
}

static void trustm_ec_keymgmt_free(void *keydata)
{
    trustm_ec_key_t *trustm_ec_key = keydata;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_ec_key == NULL)
        return;

    OPENSSL_clear_free(trustm_ec_key, sizeof(trustm_ec_key_t));
    TRUSTM_PROVIDER_DBGFN("<");
}



static int trustm_ec_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    trustm_ec_key_t *trustm_ec_key =(trustm_ec_key_t *) keydata;
    OSSL_PARAM *p;
    TRUSTM_PROVIDER_DBGFN(">");
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
    TRUSTM_PROVIDER_DBGFN("<");
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
    TRUSTM_PROVIDER_DBGFN(">");
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
    TRUSTM_PROVIDER_DBGFN("<");
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
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_ec_key == NULL)
        return 0;

    if ((selection & EC_POSSIBLE_SELECTIONS) == 0)
        return 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0))
        res = res && (trustm_ec_key->point_x_buffer_length > 0) && (trustm_ec_key->point_y_buffer_length > 0);
    TRUSTM_PROVIDER_DBGFN("<");
    return res;
}

static int trustm_ec_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    trustm_ec_key_t *pkey1 = (trustm_ec_key_t *)keydata1;
    trustm_ec_key_t *pkey2 = (trustm_ec_key_t *)keydata2;
    TRUSTM_PROVIDER_DBGFN(">");
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
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static int trustm_ec_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *)keydata;
    const OSSL_PARAM *p;
    uint8_t *private_key_data = NULL;
    size_t private_key_data_len = 0;
    BIGNUM *bn_private_key = NULL;
    char *curve_name = NULL;
    char curve_name_buf[64] = {0};
    
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_DBGFN("selection: %d (0x%X)", selection, selection); 
    if (trustm_ec_key == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) 
        {
			OSSL_PARAM_get_BN(p, &bn_private_key);
			private_key_data_len = BN_num_bytes(bn_private_key);
			
			private_key_data = (uint8_t*) OPENSSL_malloc(private_key_data_len);
			BN_bn2bin(bn_private_key, private_key_data);
			
			trustm_ec_key->private_key_id = (private_key_data[0] << 8) | private_key_data[1];
			TRUSTM_PROVIDER_DBGFN(" Private key %04X ", trustm_ec_key->private_key_id );
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL && OSSL_PARAM_get_utf8_string(p, &curve_name,sizeof(curve_name_buf))) 
        {
            if (strcmp(curve_name, "secp384r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_NIST_P_384;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: NIST P-384 (secp384r1)", curve_name_buf);
            } else if (strcmp(curve_name, "prime256v1") == 0 || strcmp(curve_name, "secp256r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_NIST_P_256;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: NIST P-256 (secp256r1)", curve_name_buf);
            } else if (strcmp(curve_name, "secp521r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_NIST_P_521;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: NIST P-521 (secp521r1)", curve_name_buf);
            } else if (strcmp(curve_name, "brainpoolP256r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: Brainpool P-256r1", curve_name_buf);
            } else if (strcmp(curve_name, "brainpoolP384r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: Brainpool P-384r1", curve_name_buf);
            } else if (strcmp(curve_name, "brainpoolP512r1") == 0) {
                trustm_ec_key->key_curve = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
                TRUSTM_PROVIDER_DBGFN("Curve name: %s, Curve: Brainpool P-512r1", curve_name_buf);
            } else {
                TRUSTM_PROVIDER_DBGFN("Unsupported curve name: %s", curve_name_buf);
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL)
        {
            if (trustm_buffer_to_ecc_point(trustm_ec_key, p->data, p->data_size) == 0)
             return 0;
        }
    }
    
    OPENSSL_free(private_key_data);
    BN_free(bn_private_key);

    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

int trustm_ec_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *)keydata;
    int curve_nid;
    int res = 0;

    void *pubbuff = NULL;
    size_t pubsize;
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_DBGFN("selection: %d (0x%X)", selection, selection); 
    if (trustm_ec_key == NULL || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)){
        TRUSTM_PROVIDER_DBGFN("<");
        return 0;
    }
    curve_nid = trustm_ecc_curve_to_nid(trustm_ec_key->key_curve);
    if (curve_nid == NID_undef) {
        TRUSTM_PROVIDER_DBGFN("Error: Invalid curve NID");
        return 0;
    }
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
    TRUSTM_PROVIDER_DBGFN("<");
    return res;
}

static const OSSL_PARAM *trustm_ec_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };

    static const OSSL_PARAM ecc_private_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return ecc_private_key_types;

    return ecc_public_key_types;
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
