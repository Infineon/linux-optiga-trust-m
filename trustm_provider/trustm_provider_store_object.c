#include <string.h>

#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_ec_key_helper.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>


typedef struct trustm_object_ctx_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    optiga_key_id_t key_id;

    optiga_rsa_key_type_t key_size;
    optiga_ecc_curve_t key_curve;
    optiga_key_usage_t key_usage;

    uint8_t new_key;
    uint8_t read_public_key_only;

    BIO *bio;

    uint8_t load_done;
} trustm_object_ctx_t;

static OSSL_FUNC_store_open_fn trustm_object_open;
static OSSL_FUNC_store_attach_fn trustm_object_attach;
static OSSL_FUNC_store_settable_ctx_params_fn trustm_object_settable_params;
static OSSL_FUNC_store_set_ctx_params_fn trustm_object_set_params;
static OSSL_FUNC_store_load_fn trustm_object_load;
static OSSL_FUNC_store_eof_fn trustm_object_eof;
static OSSL_FUNC_store_close_fn trustm_object_close;


static void *trustm_object_open(void *provctx, const char *uri)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_object_ctx_t *trustm_object_ctx;
    char *baseuri;
    char *opts[5];
    const char needle[3] = "0x";
    int i = 0;

    // scanned key id
    uint32_t key_id;
    TRUSTM_PROVIDER_DBGFN(">");    
    trustm_object_ctx = OPENSSL_zalloc(sizeof(trustm_object_ctx_t));
    if (trustm_object_ctx == NULL)
        return NULL;
    
    trustm_object_ctx->core = trustm_ctx->core;
    trustm_object_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_object_ctx->me_util = trustm_ctx->me_util;
    trustm_object_ctx->new_key = 0;
    trustm_object_ctx->read_public_key_only = 0;
    trustm_object_ctx->load_done = 0;

    if ((baseuri = OPENSSL_strdup(uri)) == NULL)
    {
        goto error;
    }

    char *ptr = strstr(baseuri, needle);
    if (ptr == NULL)
    {
        goto error;
    }

    // extract arguments
    opts[0] = strtok(baseuri, ":");
    if (opts[0] == NULL)
    {
        TRUSTM_PROVIDER_ERRFN("No OID input. Abortting...\n");
        goto error;
    }

    while (opts[i] != NULL)
    {
        i++;
        opts[i] = strtok(NULL, ":");
    }

    if (i > 6)
    {
        goto error;
    }

    // processing opts[0]
    if (strncmp(opts[0], "0x", 2) == 0)
    {
        sscanf(opts[0], "%x", &key_id);
        printf("Input OID %.4X\n", key_id);
    }

    else
        key_id = 0;

    if (((key_id < 0xE0F0) || (key_id > 0xE0F3)) &&
        ((key_id < 0xE0FC) || (key_id > 0xE0FD)))
    {
        TRUSTM_PROVIDER_ERRFN("Invalid key OID\n");
        goto error;
    }

    // assign primary key object id
    trustm_object_ctx->key_id = key_id;


    // processing opts[1]
    if (opts[1] == NULL)
    {
        TRUSTM_PROVIDER_ERRFN("Specify public key input\n");
        goto error;
    }

    // if just reading out the public key
    if (i == 2 && ((*(opts[1]) == '*') || (*(opts[1]) == '^')))
    {
        trustm_object_ctx->read_public_key_only = 1;
    }

    // if reading public key from external file
    if ((opts[1] != NULL) && (*(opts[1]) != '*') && (*(opts[1]) != '^'))
    {
        trustm_object_ctx->bio = BIO_new_file((opts[1]), "rb");
        if (trustm_object_ctx->bio == NULL)
        {
            TRUSTM_PROVIDER_ERRFN("Failed to open public key file\n");
            OPENSSL_free(baseuri);
        }
    }

    // if generating new key pair
    if ((i > 2) && (opts[2] != NULL)) 
    {
        if (!strcmp(opts[2], "NEW"))
        {
            trustm_object_ctx->new_key = 1;

            // new RSA key gen
            if ((key_id >= 0xE0FC) && (key_id <= 0xE0FD))
            {
                if (opts[3] == NULL)
                {
                    TRUSTM_PROVIDER_ERRFN("Specify key size\n");
                    goto error;
                }
                sscanf(opts[3],"%x", &(trustm_object_ctx->key_size));

                if (opts[4] == NULL)
                {
                    TRUSTM_PROVIDER_ERRFN("Specify key usage\n");
                    goto error;
                }
                sscanf(opts[4], "%x", &(trustm_object_ctx->key_usage));
            } 

            // todo: add EC key gen
            if ((key_id >= 0xE0F1) && (key_id <= 0xE0F3))
            {
                if (opts[3] == NULL)
                {
                    TRUSTM_PROVIDER_ERRFN("Specify key curve\n");
                    goto error;
                }
                sscanf(opts[3],"%x", &(trustm_object_ctx->key_curve));

                if (opts[4] == NULL)
                {
                    TRUSTM_PROVIDER_ERRFN("Specify key usage\n");
                    goto error;
                }
                sscanf(opts[4], "%x", &(trustm_object_ctx->key_usage));
            }
        }
    }

    OPENSSL_free(baseuri);
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_object_ctx;
error:
    OPENSSL_clear_free(trustm_object_ctx, sizeof(trustm_object_ctx_t));
    return NULL;
}

static void *trustm_object_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_object_ctx_t *trustm_object_ctx = OPENSSL_zalloc(sizeof(trustm_object_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_object_ctx == NULL)
        return NULL;

    trustm_object_ctx->core = trustm_ctx->core;
    trustm_object_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_object_ctx->me_util = trustm_ctx->me_util;

    trustm_object_ctx->bio = BIO_new_from_core_bio(trustm_ctx->libctx, cin);
    if (trustm_object_ctx->bio == NULL)
    {
        OPENSSL_clear_free(trustm_object_ctx, sizeof(trustm_object_ctx_t));
        return NULL;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_object_ctx; 
}

static const OSSL_PARAM *trustm_object_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int trustm_object_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    return 1;
}

static int trustm_genpkey_rsa(trustm_object_ctx_t *trustm_object_ctx)
{
    uint8_t public_key[1024];
    uint16_t public_key_length = sizeof(public_key);
    uint16_t public_key_header_length;

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
    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_object_ctx->me_crypt = me_crypt;
    trustm_object_ctx->me_util = me_util;

    if (trustm_object_ctx->key_size == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
    {
        public_key_header_length = sizeof(rsaheader2048);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = rsaheader2048[i];
    }

    else 
    {
        public_key_header_length = sizeof(rsaheader1024);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = rsaheader1024[i];
    }

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_rsa_generate_keypair(trustm_object_ctx->me_crypt, 
                                                        trustm_object_ctx->key_size,
                                                        trustm_object_ctx->key_usage,
                                                        FALSE,
                                                        &(trustm_object_ctx->key_id),
                                                        (public_key+i),
                                                        &(public_key_length));
    
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_rsa_generate_keypair\nError code : 0x%.4X\n", return_status");
        return 0;
    }

    // wait until the optiga_crypt_rsa_generate_keypair operation is completed
    printf("Generating RSA keypair using TrustM....\n");
    trustmProvider_WaitForCompletion(MAX_RSA_KEY_GEN_TIME); // can take up to 60s
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error generating RSA key pair. Return status: %d\n", return_status);
        return 0;
    }

    // saving public key to private_key_id+0x10E4
    printf("Writing public key to OID 0x%.4X\n", (trustm_object_ctx->key_id)+0x10E4);
    trustm_util_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_write_data(trustm_object_ctx->me_util,
                                            (trustm_object_ctx->key_id)+0x10E4,
                                            OPTIGA_UTIL_ERASE_AND_WRITE,
                                            0,
                                            public_key,
                                            public_key_length + i);

    if (OPTIGA_LIB_SUCCESS != return_status) 
    {
        return 0;
    }

    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT); 
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        return 0;
    }
    
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static int trustm_object_load_pkey_rsa(trustm_object_ctx_t *trustm_object_ctx, OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    optiga_lib_status_t return_status;
    trustm_metadata_t oidMetadata;
    uint8_t read_data_buffer[2048];
    uint16_t bytes_to_read = sizeof(read_data_buffer);

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

    trustm_rsa_key_t *trustm_rsa_key = NULL;
    TRUSTM_PROVIDER_DBGFN(">");    
    trustm_rsa_key = OPENSSL_zalloc(sizeof(trustm_rsa_key_t));
    if (trustm_rsa_key == NULL)
        return 0;

    trustm_rsa_key->core = trustm_object_ctx->core;
    trustm_rsa_key->me_util = trustm_object_ctx->me_util;
    trustm_rsa_key->me_crypt = trustm_object_ctx->me_crypt;
    trustm_rsa_key->private_key_id = trustm_object_ctx->key_id;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_object_ctx->me_crypt = me_crypt;
    trustm_object_ctx->me_util = me_util;

    // reading out metadata for key type/usage
    return_status = trustmProviderReadMetadata(trustm_object_ctx->me_util, trustm_object_ctx->key_id, &oidMetadata);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading metadata of OID: 0x%.4X\nError code: 0x%.4X\n", trustm_rsa_key->private_key_id + 0x10E4, return_status);
        return 0;
    }
    if (E0_algo_flag == 0)
    {
        TRUSTM_PROVIDER_ERRFN("Key is not initialized, Please Generate Key\n");
        return 0;
    }
    trustm_rsa_key->key_size = oidMetadata.E0_algo;
    trustm_rsa_key->key_usage = oidMetadata.E1_keyUsage;

    trustm_util_ShieldedConnection();
    // reading out contents in oid
    bytes_to_read = sizeof(read_data_buffer);
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_read_data(trustm_object_ctx->me_util, 
                                        (trustm_rsa_key->private_key_id + 0x10E4),
                                        0,
                                        read_data_buffer,
                                        &bytes_to_read);
    
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading contents of OID: 0x%.4X\nError code: 0x%.4X\n", trustm_rsa_key->private_key_id + 0x10E4, return_status);
        return 0;
    }
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading contents of OID: 0x%.4X\n", trustm_rsa_key->private_key_id + 0x10E4);
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    // check if we have a valid key header at all
    if (bytes_to_read < sizeof(rsaheader1024))
    {
        TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
        return 0;
    }

    if (trustm_rsa_key->key_size == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL)
    {
        if (memcmp((void *)read_data_buffer, (void *)rsaheader1024, sizeof(rsaheader1024)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key header. Please generate another key\n");
            return 0;
        }
    }

    else 
    {
        if (memcmp((void *)read_data_buffer, (void *)rsaheader2048, sizeof(rsaheader2048)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key header. Please generate another key\n");
            return 0;
        }
    }

    // filling the rsa key structure with data
    memcpy(trustm_rsa_key->public_key, read_data_buffer, bytes_to_read);
    int j = 0;

    trustm_rsa_key->public_key_length = bytes_to_read;

    if ((trustm_rsa_key->public_key[1] & 0x80) == 0x00)
        j = trustm_rsa_key->public_key[3] + 4;
    else 
    {
        j = (trustm_rsa_key->public_key[1] & 0x7f);
        j = trustm_rsa_key->public_key[j+3] + j + 4;
    }

    trustm_rsa_key->public_key_header_length = j;

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
        return 0;
    }

    trustm_rsa_key->modulus_length = tolen;
    BN_free(nbig);


    // passing the loaded key around
    int object_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[4];
    const char keytype[] = "RSA";
    int ret = 0;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &trustm_rsa_key, sizeof(trustm_rsa_key));
    params[3] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);
    TRUSTM_PROVIDER_DBGFN("<");   
    return ret;
}

static int trustm_genpkey_ec(trustm_object_ctx_t *trustm_object_ctx)
{
    optiga_lib_status_t return_status;
    int i = 0;

    uint8_t public_key[500];
    uint16_t public_key_length = sizeof(public_key);
    uint16_t public_key_header_length;


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

    TRUSTM_PROVIDER_DBGFN(">");
    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_object_ctx->me_crypt = me_crypt;
    trustm_object_ctx->me_util = me_util;

    switch (trustm_object_ctx->key_curve)
    {
        case OPTIGA_ECC_CURVE_NIST_P_256:
        public_key_header_length = sizeof(eccheader256);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheader256[i];
        
        break;

        case OPTIGA_ECC_CURVE_NIST_P_384:
        public_key_header_length = sizeof(eccheader384);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheader384[i];
        
        break;

        case OPTIGA_ECC_CURVE_NIST_P_521:
        public_key_header_length = sizeof(eccheader521);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheader521[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        public_key_header_length = sizeof(eccheaderBrainPool256);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheaderBrainPool256[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        public_key_header_length = sizeof(eccheaderBrainPool384);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheaderBrainPool384[i];
        
        break;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
        public_key_header_length = sizeof(eccheaderBrainPool512);

        for (i = 0; i < public_key_header_length; i++)
            public_key[i] = eccheaderBrainPool512[i];
        
        break;
    }

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecc_generate_keypair(trustm_object_ctx->me_crypt,
                                                    trustm_object_ctx->key_curve,
                                                    trustm_object_ctx->key_usage,
                                                    FALSE,
                                                    &(trustm_object_ctx->key_id),
                                                    (public_key+i),
                                                    &(public_key_length));

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecc_generate_keypair\nError code : 0x%.4X\n", return_status);      
        return 0;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in EC key generation\nError code : 0x%.4X\n", return_status);      
        return 0;
    } 

    uint16_t public_id = ((trustm_object_ctx->key_curve == OPTIGA_ECC_CURVE_NIST_P_521) || (trustm_object_ctx->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)) ?
                                (trustm_object_ctx->key_id + 0x10EF) : (trustm_object_ctx->key_id + 0x10E0);
    
    printf("Saving public EC key to OID : 0x%.4X ...\n", public_id);

    trustm_util_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_write_data(trustm_object_ctx->me_util, 
                                        public_id, 
                                        OPTIGA_UTIL_ERASE_AND_WRITE,
                                        0,
                                        public_key,
                                        public_key_length+i);

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        return 0;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in EC public key saving\nError code : 0x%.4X\n", return_status);
        return 0;
    }   
    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static int trustm_object_load_pkey_ec(trustm_object_ctx_t *trustm_object_ctx, OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    optiga_lib_status_t return_status;
    trustm_metadata_t oidMetadata;
    uint8_t read_data_buffer[2048];
    uint16_t bytes_to_read = sizeof(read_data_buffer);
    uint32_t public_key_offset;

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

    trustm_ec_key_t *trustm_ec_key = NULL;
    TRUSTM_PROVIDER_DBGFN(">");
    trustm_ec_key = OPENSSL_zalloc(sizeof(trustm_ec_key_t));
    if (trustm_ec_key == NULL)
        return 0;


    trustm_ec_key->core = trustm_object_ctx->core;
    trustm_ec_key->me_util = trustm_object_ctx->me_util;
    trustm_ec_key->me_crypt = trustm_object_ctx->me_crypt;
    trustm_ec_key->private_key_id = trustm_object_ctx->key_id;


    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_object_ctx->me_crypt = me_crypt;
    trustm_object_ctx->me_util = me_util;

    // reading out metadata for key type/usage
    return_status = trustmProviderReadMetadata(trustm_object_ctx->me_util, trustm_object_ctx->key_id, &oidMetadata);
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading metadata of OID: 0x%.4X\nError code: 0x%.4X\n", trustm_ec_key->private_key_id, return_status);
        return 0;
    }
    if (E0_algo_flag == 0)
    {
        TRUSTM_PROVIDER_ERRFN("Key is not initialized, Please Generate Key\n");
        return 0;
    }
    trustm_ec_key->key_curve = oidMetadata.E0_algo;
    trustm_ec_key->key_usage = oidMetadata.E1_keyUsage;

    if (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_521 || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)
        public_key_offset = 0x10EF;
    
    else 
        public_key_offset = 0x10E0;

    trustm_util_ShieldedConnection();
        // reading out contents in oid
    bytes_to_read = sizeof(read_data_buffer);
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_util_read_data(trustm_object_ctx->me_util, 
                                        (trustm_ec_key->private_key_id + public_key_offset),
                                        0,
                                        read_data_buffer,
                                        &bytes_to_read);
    
    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading contents of OID: 0x%.4X\nError code: 0x%.4X\n", trustm_ec_key->private_key_id + public_key_offset, return_status);
        return 0;
    }
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error reading contents of OID: 0x%.4X\n", trustm_ec_key->private_key_id + public_key_offset);
        return 0;
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE

    // check if we have a valid key header at all
    if (bytes_to_read < sizeof(eccheader384))
    {
        TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
        return 0;
    }

    switch (trustm_ec_key->key_curve) {
    case OPTIGA_ECC_CURVE_NIST_P_256:
        if (memcmp((void *)read_data_buffer, (void *)eccheader256, sizeof(eccheader256)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
            return 0;
        }
        break;

    case OPTIGA_ECC_CURVE_NIST_P_384:
        if (memcmp((void *)read_data_buffer, (void *)eccheader384, sizeof(eccheader384)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
            return 0;
        }
        break;    

    case OPTIGA_ECC_CURVE_NIST_P_521:
        if (memcmp((void *)read_data_buffer, (void *)eccheader521, sizeof(eccheader521)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
            return 0;
        }
        break;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        if (memcmp((void *)read_data_buffer, (void *)eccheaderBrainPool256, sizeof(eccheaderBrainPool256)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
            return 0;
        }
        break;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        if (memcmp((void *)read_data_buffer, (void *)eccheaderBrainPool384, sizeof(eccheaderBrainPool384)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key. Please generate another key\n");
            return 0;
        }
        break;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
        if (memcmp((void *)read_data_buffer, (void *)eccheaderBrainPool512, sizeof(eccheaderBrainPool512)))
        {
            TRUSTM_PROVIDER_ERRFN("Invalid public key header. Please generate another key\n");
            return 0;
        }
        break;
    }

    // filling the ec key structure with data
    memcpy(trustm_ec_key->public_key, read_data_buffer, bytes_to_read);
    int j = 0;

    trustm_ec_key->public_key_length = bytes_to_read;

    if ((trustm_ec_key->public_key[1] & 0x80) == 0x00)
        j = trustm_ec_key->public_key[3] + 4;
    else 
    {
        j = (trustm_ec_key->public_key[1] & 0x7f);
        j = trustm_ec_key->public_key[j+3] + j + 4;
    }

    trustm_ec_key->public_key_header_length = j;

    if (trustm_ecc_public_key_to_point(trustm_ec_key) == 0)
    {
        TRUSTM_PROVIDER_ERRFN("Error converting EC public key to points\n");
        return 0;
    }

    // passing the loaded key around
    int object_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[4];
    const char keytype[] = "EC";
    int ret = 0;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &trustm_ec_key, sizeof(trustm_ec_key));
    params[3] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static int trustm_object_load(void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    trustm_object_ctx_t *trustm_object_ctx = ctx;
    int ret = 0;

    TRUSTM_PROVIDER_DBGFN(">");
    // todo: implement load private key from file ig
    if (trustm_object_ctx->bio)
    {

    }

    else 
    {
        if ((trustm_object_ctx->key_id >= 0xE0FC) && (trustm_object_ctx->key_id <= 0xE0FD))
        {
            if (trustm_object_ctx->new_key)
                if (trustm_genpkey_rsa(trustm_object_ctx) == 0)
                    return 0;
            ret = trustm_object_load_pkey_rsa(trustm_object_ctx, object_cb, object_cbarg);
        }
        if ((trustm_object_ctx->key_id >= 0xE0F0) && (trustm_object_ctx->key_id <= 0xE0F3))
        {
            if (trustm_object_ctx->new_key)
                if (trustm_genpkey_ec(trustm_object_ctx) == 0)
                    return 0;
            ret = trustm_object_load_pkey_ec(trustm_object_ctx, object_cb, object_cbarg);
        }
    }

    trustm_object_ctx->load_done = 1;
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

// to do: modify this to signal eof
static int trustm_object_eof(void *ctx)
{
    trustm_object_ctx_t *trustm_object_ctx = ctx;
    return trustm_object_ctx->load_done;
}


static int trustm_object_close(void *ctx)
{
    trustm_object_ctx_t *trustm_object_ctx = ctx;

    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_object_ctx == NULL)
        return 0;
    
    BIO_free(trustm_object_ctx->bio);

    OPENSSL_clear_free(trustm_object_ctx, sizeof(trustm_object_ctx_t));
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

const OSSL_DISPATCH trustm_object_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))trustm_object_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))trustm_object_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))trustm_object_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))trustm_object_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))trustm_object_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))trustm_object_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))trustm_object_close },
    { 0, NULL }
};
