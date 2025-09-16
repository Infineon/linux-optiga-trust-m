/*
 * SPDX-FileCopyrightText: 2025 Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>

#include "trustm_provider_common.h"
#include "trustm_key_helper.h"


typedef struct trustm_keyexch_ctx_str {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;

    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    trustm_ec_key_t *trustm_private_ec_key;

    uint8_t peer_buffer[300];
    uint16_t peer_buffer_length;
    optiga_ecc_curve_t peer_curve;

    /* KDF settings */
    char kdf_name[TRUSTM_MAX_OSSL_NAME];
    char kdf_hash[TRUSTM_MAX_OSSL_NAME];
    char *kdf_propq;
    size_t kdf_outlen;
    void *kdf_ukmptr;
    size_t kdf_ukmlen;
} trustm_keyexch_ctx_t;


static OSSL_FUNC_keyexch_newctx_fn trustm_keyexch_newctx;
static OSSL_FUNC_keyexch_init_fn trustm_keyexch_init;
static OSSL_FUNC_keyexch_set_peer_fn trustm_keyexch_set_peer;
static OSSL_FUNC_keyexch_derive_fn trustm_keyexch_derive;
static OSSL_FUNC_keyexch_freectx_fn trustm_keyexch_freectx;
static OSSL_FUNC_keyexch_set_ctx_params_fn trustm_keyexch_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn trustm_keyexch_settable_ctx_params;


static void *trustm_keyexch_newctx(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = OPENSSL_zalloc(sizeof(trustm_keyexch_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_keyexch_ctx == NULL)
        return NULL;

    trustm_keyexch_ctx->core = trustm_ctx->core;
    trustm_keyexch_ctx->libctx =trustm_ctx->libctx;
    trustm_keyexch_ctx->me_crypt = trustm_ctx->me_crypt;
    trustm_keyexch_ctx->me_util = trustm_ctx->me_util;
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_keyexch_ctx;
}


static void trustm_keyexch_freectx(void *ctx)
{
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = ctx;

    if (trustm_keyexch_ctx == NULL)
        return;

    OPENSSL_free(trustm_keyexch_ctx->kdf_propq);
    OPENSSL_clear_free(trustm_keyexch_ctx->kdf_ukmptr, trustm_keyexch_ctx->kdf_ukmlen);
    OPENSSL_clear_free(trustm_keyexch_ctx, sizeof(trustm_keyexch_ctx_t));
}


static int trustm_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = ctx;
    trustm_keyexch_ctx->trustm_private_ec_key = provkey;

    return trustm_keyexch_set_ctx_params(trustm_keyexch_ctx, params);
}

static int trustm_keyexch_set_peer(void *ctx, void *provkey)
{
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = ctx;
    trustm_ec_key_t *peerkey = provkey;

    void *uncompressed_peerkey_buffer;
    uint16_t uncompressed_peerkey_buffer_length;

    // getting peerkey ec uncompressed buffer
    uncompressed_peerkey_buffer_length = trustm_ec_point_to_uncompressed_buffer(peerkey, (void **)&uncompressed_peerkey_buffer);

    trustm_keyexch_ctx->peer_buffer[0] = 0x03;
    TRUSTM_PROVIDER_DBGFN(">");
    if (peerkey->key_curve == OPTIGA_ECC_CURVE_NIST_P_521 
            || peerkey->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)
    {
        trustm_keyexch_ctx->peer_buffer[1] = 0x81;
        trustm_keyexch_ctx->peer_buffer[2] = uncompressed_peerkey_buffer_length + 1;
        trustm_keyexch_ctx->peer_buffer[3] = 0x00;

        // copy uncompressed form into buffer
        memcpy(trustm_keyexch_ctx->peer_buffer+4, uncompressed_peerkey_buffer, uncompressed_peerkey_buffer_length);

        trustm_keyexch_ctx->peer_buffer_length = uncompressed_peerkey_buffer_length + 4;
    }

    else 
    {
        trustm_keyexch_ctx->peer_buffer[1] = uncompressed_peerkey_buffer_length + 1;
        trustm_keyexch_ctx->peer_buffer[2] = 0x00;

        // copy uncompressed form into buffer
        memcpy(trustm_keyexch_ctx->peer_buffer+3, uncompressed_peerkey_buffer, uncompressed_peerkey_buffer_length);

        trustm_keyexch_ctx->peer_buffer_length = uncompressed_peerkey_buffer_length + 3;
    }

    trustm_keyexch_ctx->peer_curve = peerkey->key_curve;
    
    OPENSSL_free(uncompressed_peerkey_buffer);
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static int trustm_keyexch_derive_kdf(trustm_keyexch_ctx_t *trustm_keyexch_ctx, unsigned char *secret,
                                        size_t *secretlen, size_t outlen)
{
    optiga_lib_status_t return_status;
    uint8_t shared_secret[66];
    uint16_t shared_secret_length;
    public_key_from_host_t peer_public_key_details;
    
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;
    int res = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    if (secret == NULL)
    {
        *secretlen = trustm_keyexch_ctx->kdf_outlen;
        return 1;
    }

    if (trustm_keyexch_ctx->kdf_outlen > outlen)
    {
        TRUSTM_PROVIDER_ERRFN("Error kdf_outlen : %d  larger than outlen : %d\n", trustm_keyexch_ctx->kdf_outlen, outlen);
        return 0;
    }

    if (trustm_keyexch_ctx->peer_curve != trustm_keyexch_ctx->trustm_private_ec_key->key_curve)
    {
        TRUSTM_PROVIDER_ERRFN("Mismatching key curves\n");
        return 0;
    }

    peer_public_key_details.public_key = trustm_keyexch_ctx->peer_buffer;
    peer_public_key_details.length = trustm_keyexch_ctx->peer_buffer_length;
    peer_public_key_details.key_type = trustm_keyexch_ctx->peer_curve;

    if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_NIST_P_256 
        || trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1)
        shared_secret_length = 32;

    else if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_NIST_P_384 
        || trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)
        shared_secret_length = 48;

    else if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)
        shared_secret_length = 64;

    else 
        shared_secret_length = 66;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_keyexch_ctx->me_crypt = me_crypt;

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdh(trustm_keyexch_ctx->me_crypt, 
                                    trustm_keyexch_ctx->trustm_private_ec_key->private_key_id,
                                    &peer_public_key_details,
                                    TRUE,
                                    shared_secret);

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecdh\nError code : 0x%.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_keyexch_derive_kdf\nError code : 0x%.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }  


    if ((kdf = EVP_KDF_fetch(trustm_keyexch_ctx->libctx, trustm_keyexch_ctx->kdf_name, trustm_keyexch_ctx->kdf_propq)) == NULL
        || (kctx = EVP_KDF_CTX_new(kdf)) == NULL)
    {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, trustm_keyexch_ctx->kdf_hash, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared_secret, shared_secret_length);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, trustm_keyexch_ctx->kdf_ukmptr, trustm_keyexch_ctx->kdf_ukmlen);
    *p = OSSL_PARAM_construct_end();

    res = EVP_KDF_derive(kctx, secret, outlen, params) > 0;
    *secretlen = trustm_keyexch_ctx->kdf_outlen;

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE


    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    TRUSTM_PROVIDER_DBGFN("<");
    return res;
}

static int trustm_keyexch_derive_plain(trustm_keyexch_ctx_t *trustm_keyexch_ctx, unsigned char *secret,
                                        size_t *secretlen, size_t outlen)
{
    optiga_lib_status_t return_status;
    uint8_t shared_secret[66];
    uint16_t shared_secret_length;
    public_key_from_host_t peer_public_key_details;
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_keyexch_ctx->peer_curve != trustm_keyexch_ctx->trustm_private_ec_key->key_curve)
    {
        TRUSTM_PROVIDER_ERRFN("Error mismatching key curves\n");
        return 0;
    }

    peer_public_key_details.public_key = trustm_keyexch_ctx->peer_buffer;
    peer_public_key_details.length = trustm_keyexch_ctx->peer_buffer_length;
    peer_public_key_details.key_type = trustm_keyexch_ctx->peer_curve;

    if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_NIST_P_256 
        || trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1)
        shared_secret_length = 32;

    else if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_NIST_P_384 
        || trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)
        shared_secret_length = 48;

    else if (trustm_keyexch_ctx->peer_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1)
        shared_secret_length = 64;

    else 
        shared_secret_length = 66;

    TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE
    trustm_keyexch_ctx->me_crypt = me_crypt;

    trustm_crypt_ShieldedConnection();
    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_ecdh(trustm_keyexch_ctx->me_crypt, 
                                    trustm_keyexch_ctx->trustm_private_ec_key->private_key_id,
                                    &peer_public_key_details,
                                    TRUE,
                                    shared_secret);

    if (OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_PROVIDER_ERRFN("Error in optiga_crypt_ecdh\nError code : 0x%.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }
    
    trustmProvider_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    return_status = optiga_lib_status;

    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        TRUSTM_PROVIDER_ERRFN("Error in trustm_keyexch_derive_plain\nError code : 0x%.4X\n", return_status);
        TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
        return 0;
    }   

    *secretlen = shared_secret_length;
    if (secret != NULL)
    {
        if (*secretlen > outlen)
        {
            TRUSTM_PROVIDER_ERRFN("Error secretlen  :  %d   larger than outlen  :  %d\n", *secretlen, outlen);
            TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
            return 0;
        }
        memcpy(secret, shared_secret, *secretlen);
    }

    TRUSTM_PROVIDER_SSL_MUTEX_RELEASE
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}


static int trustm_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = ctx;

    if (trustm_keyexch_ctx->kdf_name[0])
        return trustm_keyexch_derive_kdf(trustm_keyexch_ctx, secret, secretlen, outlen);
    else
        return trustm_keyexch_derive_plain(trustm_keyexch_ctx, secret, secretlen, outlen);
}

static int trustm_keyexch_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    trustm_keyexch_ctx_t *trustm_keyexch_ctx = ctx;
    const OSSL_PARAM *p;
    TRUSTM_PROVIDER_DBGFN(">");
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL)
    {
        char *pname = trustm_keyexch_ctx->kdf_name;
        if (!OSSL_PARAM_get_utf8_string(p, &pname, TRUSTM_MAX_OSSL_NAME))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL)
    {
        char *pname = trustm_keyexch_ctx->kdf_hash;
        if (!OSSL_PARAM_get_utf8_string(p, &pname, TRUSTM_MAX_OSSL_NAME))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
    if (p != NULL)
    {
        OPENSSL_free(trustm_keyexch_ctx->kdf_propq);
        trustm_keyexch_ctx->kdf_propq = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &trustm_keyexch_ctx->kdf_propq, 0))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &trustm_keyexch_ctx->kdf_outlen))
        return 0;   

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL)
    {
        OPENSSL_clear_free(trustm_keyexch_ctx->kdf_ukmptr, trustm_keyexch_ctx->kdf_ukmlen);
        trustm_keyexch_ctx->kdf_ukmptr = NULL;

        if (!OSSL_PARAM_get_octet_string(p, &trustm_keyexch_ctx->kdf_ukmptr, 0, &trustm_keyexch_ctx->kdf_ukmlen))
            return 0;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

static const OSSL_PARAM *trustm_keyexch_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

const OSSL_DISPATCH trustm_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void(*)(void))trustm_keyexch_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void(*)(void))trustm_keyexch_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void(*)(void))trustm_keyexch_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void(*)(void))trustm_keyexch_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void(*)(void))trustm_keyexch_freectx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void(*)(void))trustm_keyexch_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void(*)(void))trustm_keyexch_settable_ctx_params },
    { 0, NULL }
};
