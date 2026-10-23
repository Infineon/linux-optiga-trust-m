/**
* SPDX-FileCopyrightText: 2020-2026 Infineon Technologies AG
* SPDX-License-Identifier: MIT
*
* \author Infineon Technologies AG
*
* \file pal_crypt_psa.c
*
* \brief   This file implements APIs, types and data structures used for
*          protected update pal crypt, ported to Mbed TLS 4.x / TF-PSA-Crypto 1.x.
*
*          The Mbed TLS 4.x public API surface no longer exposes the low level
*          ECP / RSA structures via mbedtls_pk_context, and RNG for signing is
*          taken from PSA internally. This implementation therefore uses the
*          PSA Crypto API for symmetric / hash / KDF / RNG primitives and the
*          mbedtls_pk_* + PSA bridge (mbedtls_pk_import_into_psa) for key
*          parsing, signing and component extraction.
*
* \ingroup  grProtectedUpdateTool
*
* @{
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <mbedtls/pk.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <psa/crypto.h>

#include "pal/pal_crypt.h"
#include "pal/pal_logger.h"
#include "pal/pal_os_memory.h"
#include "protected_update_data_set.h"

/* PSA crypto initialization is performed exactly once across all threads. */
static pthread_once_t pal_psa_init_once_ctl = PTHREAD_ONCE_INIT;
static psa_status_t pal_psa_init_status = PSA_ERROR_BAD_STATE;

static void pal_psa_do_init(void)
{
    pal_psa_init_status = psa_crypto_init();
}

static psa_status_t pal_psa_init_once(void)
{
    (void)pthread_once(&pal_psa_init_once_ctl, pal_psa_do_init);
    return pal_psa_init_status;
}

/*----------------------------------------------------------------------------
 * PEM file helpers
 *
 * This helper slurps a PEM file into a heap buffer, guaranteeing a trailing NUL 
 * as required by mbedtls_pk_parse_key() for PEM inputs (keylen == strlen + 1).
 *---------------------------------------------------------------------------*/
static int pal_crypt_load_pem_file(const char *path,
                                   unsigned char **out_buf,
                                   size_t *out_len)
{
    int status = -1;
    FILE *fp = NULL;
    long filelen = 0;
    unsigned char *buf = NULL;

    if (NULL == path || NULL == out_buf || NULL == out_len)
    {
        return -1;
    }
    *out_buf = NULL;
    *out_len = 0;

    do
    {
        fp = fopen(path, "rb");
        if (NULL == fp)
        {
            break;
        }
        if (0 != fseek(fp, 0, SEEK_END))
        {
            break;
        }
        filelen = ftell(fp);
        if (filelen < 0)
        {
            break;
        }
        rewind(fp);

        buf = (unsigned char *)pal_os_malloc((uint32_t)(filelen + 1));
        if (NULL == buf)
        {
            break;
        }
        if (filelen > 0 && 1 != fread(buf, (size_t)filelen, 1, fp))
        {
            break;
        }
        buf[filelen] = '\0';
        *out_buf = buf;
        *out_len = (size_t)filelen + 1U; /* Include the trailing NUL for PEM. */
        buf = NULL;
        status = 0;
    } while (0);

    if (NULL != buf)
    {
        pal_os_free(buf);
    }
    if (NULL != fp)
    {
        (void)fclose(fp);
    }
    return status;
}

static void pal_crypt_release_pem_file(unsigned char *buf, size_t len)
{
    if (NULL != buf)
    {
        memset(buf, 0, len);
        pal_os_free(buf);
    }
}

static int pal_crypt_parse_pk_from_file(mbedtls_pk_context *ctx, const char *path)
{
    unsigned char *pem = NULL;
    size_t pem_len = 0;
    int ret;

    if (0 != pal_crypt_load_pem_file(path, &pem, &pem_len))
    {
        return -1;
    }
    ret = mbedtls_pk_parse_key(ctx, pem, pem_len, NULL, 0);
    pal_crypt_release_pem_file(pem, pem_len);
    return ret;
}

/*----------------------------------------------------------------------------
 * SHA-256 hash
 *---------------------------------------------------------------------------*/
static uint16_t pal_crypt_calculate_sha256_hash(const uint8_t *message,
                                                uint16_t message_len,
                                                uint8_t *digest)
{
    uint16_t status = 1;
    size_t out_len = 0;

    if (pal_psa_init_once() != PSA_SUCCESS)
    {
        pal_logger_print_message(" Error : Failed in psa_crypto_init\n");
        return status;
    }

    if (PSA_SUCCESS == psa_hash_compute(PSA_ALG_SHA_256,
                                        message,
                                        message_len,
                                        digest,
                                        32,
                                        &out_len)
        && out_len == 32)
    {
        status = 0;
    }
    else
    {
        pal_logger_print_message(" Error : Failed in psa_hash_compute (SHA-256)\n");
    }
    return status;
}

//lint --e{715} suppress "argument \"p_pal_crypt\" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_hash(pal_crypt_t *p_pal_crypt,
                            uint8_t hash_algorithm,
                            const uint8_t *p_message,
                            uint32_t message_length,
                            uint8_t *p_digest)
{
    (void)p_pal_crypt;
    pal_status_t status = 1;

    if ((uint8_t)eSHA_256 == hash_algorithm)
    {
        status = pal_crypt_calculate_sha256_hash(p_message, (uint16_t)message_length, p_digest);
    }
    return status;
}

/*----------------------------------------------------------------------------
 * PK helpers
 *---------------------------------------------------------------------------*/
pal_status_t pal_crypt_get_signature_length(uint8_t *p_private_key,
                                            uint16_t *sign_len,
                                            signature_algo_t sign_algo)
{
    pal_status_t status = 1;
    mbedtls_pk_context ctx;
    psa_key_type_t key_type;
    size_t nbits;

    mbedtls_pk_init(&ctx);
    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            pal_logger_print_message(" Error : Failed in psa_crypto_init\n");
            break;
        }
        if (0 != pal_crypt_parse_pk_from_file(&ctx, (const char *)p_private_key))
        {
            pal_logger_print_message(" Error : Failed in mbedtls_pk_parse_key\n");
            break;
        }

        key_type = mbedtls_pk_get_key_type(&ctx);
        nbits = mbedtls_pk_get_bitlen(&ctx);

        if (eES_SHA == sign_algo)
        {
            if (PSA_KEY_TYPE_IS_ECC(key_type))
            {
                /* Raw ECDSA r||s length = 2 * ceil(nbits/8). */
                *sign_len = (uint16_t)(2U * ((nbits + 7U) / 8U));
            }
            else
            {
                pal_logger_print_message(" Error : Key type mismatch (expected ECC)\n");
                break;
            }
        }
        else if (eRSA_SSA_PKCS1_V1_5_SHA_256 == sign_algo)
        {
            if (PSA_KEY_TYPE_IS_RSA(key_type))
            {
                *sign_len = (uint16_t)((nbits + 7U) / 8U);
            }
            else
            {
                pal_logger_print_message(" Error : Key type mismatch (expected RSA)\n");
                break;
            }
        }
        else
        {
            pal_logger_print_message(" Error : Invalid sign algo\n");
            break;
        }
        status = 0;
    } while (0);

    mbedtls_pk_free(&ctx);
    return status;
}

//lint --e{715} suppress "arguments not used in the implementation but kept for future use"
pal_status_t pal_crypt_sign(pal_crypt_t *p_pal_crypt,
                            uint8_t *p_digest,
                            uint16_t digest_length,
                            uint8_t *p_signature,
                            uint16_t *signature_length,
                            const uint8_t *p_private_key,
                            uint16_t private_key_length)
{
    (void)p_pal_crypt;
    (void)private_key_length;

    pal_status_t status = 1;
    mbedtls_pk_context ctx;
    uint8_t hash[32];
    size_t sig_out_len = 0;

    mbedtls_pk_init(&ctx);
    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            pal_logger_print_message(" Error : Failed in psa_crypto_init\n");
            break;
        }

        if (0 != pal_crypt_parse_pk_from_file(&ctx, (const char *)p_private_key))
        {
            pal_logger_print_message(" Error : Failed in mbedtls_pk_parse_key\n");
            break;
        }

        if (0 != pal_crypt_hash(NULL, (uint8_t)eSHA_256, p_digest, digest_length, hash))
        {
            pal_logger_print_message(" Error : Failed in pal_crypt_hash\n");
            break;
        }

        /* In Mbed TLS 4.x, mbedtls_pk_sign() takes an explicit output buffer
         * size and derives its RNG from PSA internally. */
        if (0 != mbedtls_pk_sign(&ctx,
                                 MBEDTLS_MD_SHA256,
                                 hash,
                                 sizeof(hash),
                                 p_signature,
                                 (size_t)(*signature_length),
                                 &sig_out_len))
        {
            pal_logger_print_message(" Error : Failed in mbedtls_pk_sign\n");
            break;
        }
        *signature_length = (uint16_t)sig_out_len;
        status = 0;
    } while (0);

    mbedtls_pk_free(&ctx);
    return status;
}

/*----------------------------------------------------------------------------
 * AES-128-CCM
 *---------------------------------------------------------------------------*/
#define PAL_CRYPT_AES128_KEY_BYTES (16U)

//lint --e{715} suppress "argument \"p_pal_crypt\" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_encrypt_aes128_ccm(pal_crypt_t *p_pal_crypt,
                                          const uint8_t *p_plain_text,
                                          uint16_t plain_text_length,
                                          const uint8_t *p_encrypt_key,
                                          const uint8_t *p_nonce,
                                          uint16_t nonce_length,
                                          const uint8_t *p_associated_data,
                                          uint16_t associated_data_length,
                                          uint8_t mac_size,
                                          uint8_t *p_cipher_text)
{
    (void)p_pal_crypt;

    pal_status_t status = 1;
    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    int key_imported = 0;
    size_t out_len = 0;
    psa_algorithm_t alg;

    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            break;
        }

        alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mac_size);

        psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attr, PAL_CRYPT_AES128_KEY_BYTES * 8U);
        psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attr, alg);

        st = psa_import_key(&attr, p_encrypt_key, PAL_CRYPT_AES128_KEY_BYTES, &key_id);
        psa_reset_key_attributes(&attr);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        key_imported = 1;

        /* Output layout expected by the caller: ciphertext || tag */
        st = psa_aead_encrypt(key_id,
                              alg,
                              p_nonce,
                              nonce_length,
                              p_associated_data,
                              associated_data_length,
                              p_plain_text,
                              plain_text_length,
                              p_cipher_text,
                              (size_t)plain_text_length + mac_size,
                              &out_len);
        if (st == PSA_SUCCESS && out_len == (size_t)plain_text_length + mac_size)
        {
            status = 0;
        }
    } while (0);

    if (key_imported)
    {
        (void)psa_destroy_key(key_id);
    }
    return status;
}

/*----------------------------------------------------------------------------
 * TLS 1.2 PRF SHA-256 (used as KDF)
 *---------------------------------------------------------------------------*/
#define PAL_CRYPT_MAX_LABEL_SEED_LENGTH (96U)

//lint --e{715} suppress "argument \"p_pal_crypt\" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_tls_prf_sha256(pal_crypt_t *p_pal_crypt,
                                      const uint8_t *p_secret,
                                      uint16_t secret_length,
                                      const uint8_t *p_label,
                                      uint16_t label_length,
                                      const uint8_t *p_seed,
                                      uint16_t seed_length,
                                      uint8_t *p_derived_key,
                                      uint16_t derived_key_length)
{
    (void)p_pal_crypt;

    pal_status_t return_value = 1;
    psa_status_t st;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    int key_imported = 0;
    psa_algorithm_t alg = PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            break;
        }
        if ((uint32_t)label_length + (uint32_t)seed_length > PAL_CRYPT_MAX_LABEL_SEED_LENGTH)
        {
            break;
        }

        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attr, alg);
        psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
        st = psa_import_key(&attr, p_secret, (size_t)secret_length, &key_id);
        psa_reset_key_attributes(&attr);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        key_imported = 1;

        st = psa_key_derivation_setup(&operation, alg);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        st = psa_key_derivation_set_capacity(&operation, derived_key_length);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        st = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SEED,
                                            p_seed,
                                            seed_length);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        st = psa_key_derivation_input_key(&operation,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          key_id);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        st = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_LABEL,
                                            p_label,
                                            label_length);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        st = psa_key_derivation_output_bytes(&operation,
                                             p_derived_key,
                                             derived_key_length);
        if (st != PSA_SUCCESS)
        {
            break;
        }
        return_value = 0;
    } while (0);

    (void)psa_key_derivation_abort(&operation);
    if (key_imported)
    {
        (void)psa_destroy_key(key_id);
    }

    if (0 != return_value && NULL != p_derived_key)
    {
        memset(p_derived_key, 0, derived_key_length);
    }
    return return_value;
}

/*----------------------------------------------------------------------------
 * RNG
 *---------------------------------------------------------------------------*/
//lint --e{715} suppress "argument \"p_pal_crypt\" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_generate_random(pal_crypt_t *p_pal_crypt,
                                       uint8_t *p_random_data,
                                       uint16_t random_data_length)
{
    (void)p_pal_crypt;

    if (pal_psa_init_once() != PSA_SUCCESS)
    {
        pal_logger_print_message(" Error : Failed in psa_crypto_init\n");
        return 1;
    }
    if (PSA_SUCCESS != psa_generate_random(p_random_data, random_data_length))
    {
        pal_logger_print_message(" Error : Failed in psa_generate_random\n");
        return 1;
    }
    return 0;
}

//lint --e{715} suppress "argument \"p_pal_crypt\" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_set_seed(pal_crypt_t *p_pal_crypt,
                                uint8_t *p_seed,
                                uint16_t seed_length)
{
    return pal_crypt_generate_random(p_pal_crypt, p_seed, seed_length);
}

/*----------------------------------------------------------------------------
 * Key type detection
 *---------------------------------------------------------------------------*/
pal_status_t pal_crypt_get_key_type(int8_t *key_file)
{
    pal_status_t status = 1;
    mbedtls_pk_context ctx;
    psa_key_type_t key_type;

    mbedtls_pk_init(&ctx);
    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            pal_logger_print_message("Error : psa_crypto_init failed\n");
            break;
        }
        if (0 != pal_crypt_parse_pk_from_file(&ctx, (const char *)key_file))
        {
            pal_logger_print_message("Error : Parsing of the key file\n");
            break;
        }
        key_type = mbedtls_pk_get_key_type(&ctx);
        if (PSA_KEY_TYPE_IS_RSA(key_type))
        {
            status = (uint16_t)eRSA;
        }
        else if (PSA_KEY_TYPE_IS_ECC(key_type))
        {
            status = (uint16_t)eECC;
        }
    } while (0);

    mbedtls_pk_free(&ctx);
    return status;
}

/*----------------------------------------------------------------------------
 * ECC / RSA raw component extraction via PSA export
 *---------------------------------------------------------------------------*/
static inline void pal_crypt_set_buffer(uint8_t **dest, uint16_t *dest_len, uint16_t len)
{
    *dest = pal_os_malloc(len);
    *dest_len = len;
}

pal_status_t pal_crypt_parse_ecc_key(void *key_file,
                                     uint8_t **D, uint16_t *D_length,
                                     uint8_t **X, uint16_t *X_length,
                                     uint8_t **Y, uint16_t *Y_length)
{
    pal_status_t status = 1;
    mbedtls_pk_context ctx;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    int key_imported = 0;
    uint8_t priv_buf[PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    uint8_t pub_buf[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    size_t priv_len = 0;
    size_t pub_len = 0;
    size_t coord_bytes = 0;

    mbedtls_pk_init(&ctx);
    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            pal_logger_print_message("Error : psa_crypto_init failed\n");
            break;
        }
        if (0 != pal_crypt_parse_pk_from_file(&ctx, (const char *)key_file))
        {
            pal_logger_print_message("Error : Parsing of the ecc key file\n");
            break;
        }

        if (0 != mbedtls_pk_get_psa_attributes(&ctx, PSA_KEY_USAGE_SIGN_HASH, &attr))
        {
            pal_logger_print_message("Error : mbedtls_pk_get_psa_attributes\n");
            break;
        }
        if (0 != mbedtls_pk_import_into_psa(&ctx, &attr, &key_id))
        {
            psa_reset_key_attributes(&attr);
            pal_logger_print_message("Error : mbedtls_pk_import_into_psa\n");
            break;
        }
        psa_reset_key_attributes(&attr);
        key_imported = 1;

        /* Coordinate size in bytes derived from curve bit length. */
        coord_bytes = (mbedtls_pk_get_bitlen(&ctx) + 7U) / 8U;

        /* Private scalar: raw big-endian, coord_bytes long. */
        if (PSA_SUCCESS != psa_export_key(key_id, priv_buf, sizeof(priv_buf), &priv_len)
            || priv_len != coord_bytes)
        {
            pal_logger_print_message("Error : psa_export_key (ecc private)\n");
            break;
        }

        /* Public key: uncompressed 0x04 || X || Y, so 1 + 2*coord_bytes. */
        if (PSA_SUCCESS != psa_export_public_key(key_id, pub_buf, sizeof(pub_buf), &pub_len)
            || pub_len != 1U + 2U * coord_bytes
            || pub_buf[0] != 0x04)
        {
            pal_logger_print_message("Error : psa_export_public_key (ecc)\n");
            break;
        }

        pal_crypt_set_buffer(D, D_length, (uint16_t)coord_bytes);
        pal_crypt_set_buffer(X, X_length, (uint16_t)coord_bytes);
        pal_crypt_set_buffer(Y, Y_length, (uint16_t)coord_bytes);

        memcpy(*D, priv_buf, coord_bytes);
        memcpy(*X, pub_buf + 1, coord_bytes);
        memcpy(*Y, pub_buf + 1 + coord_bytes, coord_bytes);

        status = 0;
    } while (0);

    /* Wipe intermediate buffers containing key material. */
    memset(priv_buf, 0, sizeof(priv_buf));
    memset(pub_buf, 0, sizeof(pub_buf));

    if (key_imported)
    {
        (void)psa_destroy_key(key_id);
    }
    mbedtls_pk_free(&ctx);
    return status;
}

/*
 * Parse an ASN.1 INTEGER from a PKCS#1 RSAPrivateKey DER blob, dropping a
 * leading 0x00 padding byte if present. The bytes are copied into a freshly
 * allocated buffer.
 */
static int pal_crypt_asn1_get_uint_bytes(unsigned char **p,
                                         const unsigned char *end,
                                         uint8_t **out, uint16_t *out_len)
{
    size_t len = 0;
    if (0 != mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER))
    {
        return -1;
    }
    /* Strip a single leading 0x00 that indicates a positive INTEGER. */
    if (len > 1 && (*p)[0] == 0x00)
    {
        (*p)++;
        len--;
    }
    if (len == 0 || len > 0xFFFFU)
    {
        return -1;
    }
    *out = pal_os_malloc((uint16_t)len);
    if (NULL == *out)
    {
        return -1;
    }
    memcpy(*out, *p, len);
    *out_len = (uint16_t)len;
    *p += len;
    return 0;
}

pal_status_t pal_crypt_parse_rsa_key(void *key_file,
                                     uint8_t **N, uint16_t *N_length,
                                     uint8_t **E, uint16_t *E_length,
                                     uint8_t **D, uint16_t *D_length)
{
    pal_status_t status = 1;
    mbedtls_pk_context ctx;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    int key_imported = 0;
    uint8_t *der_buf = NULL;
    size_t der_bufsz = 0;
    size_t der_len = 0;
    unsigned char *p = NULL;
    const unsigned char *end = NULL;
    size_t seq_len = 0;
    uint8_t *tmp = NULL;
    uint16_t tmp_len = 0;

    mbedtls_pk_init(&ctx);
    do
    {
        if (pal_psa_init_once() != PSA_SUCCESS)
        {
            pal_logger_print_message("Error : psa_crypto_init failed\n");
            break;
        }
        if (0 != pal_crypt_parse_pk_from_file(&ctx, (const char *)key_file))
        {
            pal_logger_print_message("Error : Parsing of the rsa key file\n");
            break;
        }

        if (0 != mbedtls_pk_get_psa_attributes(&ctx, PSA_KEY_USAGE_SIGN_HASH, &attr))
        {
            pal_logger_print_message("Error : mbedtls_pk_get_psa_attributes\n");
            break;
        }
        if (0 != mbedtls_pk_import_into_psa(&ctx, &attr, &key_id))
        {
            psa_reset_key_attributes(&attr);
            pal_logger_print_message("Error : mbedtls_pk_import_into_psa\n");
            break;
        }
        psa_reset_key_attributes(&attr);
        key_imported = 1;

        /*
         * psa_export_key() for an RSA key pair returns a PKCS#1 DER-encoded
         *   RSAPrivateKey ::= SEQUENCE {
         *       version, n, e, d, p, q, dp, dq, qinv, ... }
         *
         * Reserve enough room for a large RSA key (up to PSA_VENDOR_RSA_MAX_KEY_BITS).
         */
        der_bufsz = PSA_EXPORT_KEY_PAIR_MAX_SIZE;
        der_buf = pal_os_malloc((uint16_t)der_bufsz);
        if (NULL == der_buf)
        {
            pal_logger_print_message("Error : allocation for RSA DER buffer\n");
            break;
        }
        if (PSA_SUCCESS != psa_export_key(key_id, der_buf, der_bufsz, &der_len))
        {
            pal_logger_print_message("Error : psa_export_key (rsa)\n");
            break;
        }

        p = der_buf;
        end = der_buf + der_len;

        if (0 != mbedtls_asn1_get_tag(&p, end, &seq_len,
                                      MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        {
            pal_logger_print_message("Error : ASN.1 SEQUENCE in RSA DER\n");
            break;
        }
        end = p + seq_len;

        /* version INTEGER */
        if (0 != mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_INTEGER))
        {
            pal_logger_print_message("Error : ASN.1 version in RSA DER\n");
            break;
        }
        p += seq_len;

        /* n INTEGER */
        if (0 != pal_crypt_asn1_get_uint_bytes(&p, end, N, N_length))
        {
            pal_logger_print_message("Error : ASN.1 modulus (N)\n");
            break;
        }
        /* e INTEGER */
        if (0 != pal_crypt_asn1_get_uint_bytes(&p, end, E, E_length))
        {
            pal_logger_print_message("Error : ASN.1 public exponent (E)\n");
            break;
        }
        /* d INTEGER */
        if (0 != pal_crypt_asn1_get_uint_bytes(&p, end, D, D_length))
        {
            pal_logger_print_message("Error : ASN.1 private exponent (D)\n");
            break;
        }

        /*
         * Historically pal_crypt_parse_rsa_key() returned E in a fixed 4-byte
         * buffer. Preserve that ABI to avoid surprising callers by re-packing
         * a shorter exponent (e.g. F4 = 0x010001) into 4 bytes MSB-first.
         */
        if (*E_length < 4U)
        {
            tmp = pal_os_malloc(4U);
            if (NULL == tmp)
            {
                break;
            }
            memset(tmp, 0, 4U);
            memcpy(tmp + (4U - *E_length), *E, *E_length);
            pal_os_free(*E);
            *E = tmp;
            tmp_len = 4U;
            *E_length = tmp_len;
        }

        status = 0;
    } while (0);

    if (NULL != der_buf)
    {
        memset(der_buf, 0, der_bufsz);
        pal_os_free(der_buf);
    }
    if (key_imported)
    {
        (void)psa_destroy_key(key_id);
    }
    mbedtls_pk_free(&ctx);
    return status;
}

/**
* @}
*/
