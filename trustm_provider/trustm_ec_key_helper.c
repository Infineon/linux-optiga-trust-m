#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_ec_key_helper.h"


// helper function to return NID from trustm ecc curve name
int trustm_ecc_curve_to_nid(optiga_ecc_curve_t curve)
{
    switch (curve) {
    case OPTIGA_ECC_CURVE_NIST_P_256:
        return NID_X9_62_prime256v1;
    
    case OPTIGA_ECC_CURVE_NIST_P_384:
        return NID_secp384r1;

    case OPTIGA_ECC_CURVE_NIST_P_521:
        return NID_secp521r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        return NID_brainpoolP256r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        return NID_brainpoolP384r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
        return NID_brainpoolP512r1;

    default:
        return NID_undef;
    }
}

// helper function to return trustm ecc curve name from NID
optiga_ecc_curve_t trustm_nid_to_ecc_curve(int nid)
{
    switch (nid) {
    case NID_X9_62_prime256v1:
        return OPTIGA_ECC_CURVE_NIST_P_256;

    case NID_secp384r1:
        return OPTIGA_ECC_CURVE_NIST_P_384;

    case NID_secp521r1:
        return OPTIGA_ECC_CURVE_NIST_P_521;

    case NID_brainpoolP256r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;

    case NID_brainpoolP384r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;

    case NID_brainpoolP512r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;

    default:
        return 0;
    }
}

// helper function to convert trustm's generated public key to ecc points
int trustm_ecc_public_key_to_point(trustm_ec_key_t *trustm_ec_key)
{
    EC_GROUP* group = NULL;
    EC_POINT* point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    uint8_t uncompressed_buff[500];
    uint16_t uncompressed_buff_length;
    int res = 0;
    int tolen;

    if (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_256 || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_384
        || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1 || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)
    {
        uncompressed_buff_length = trustm_ec_key->public_key[trustm_ec_key->public_key_header_length + 1] - 1;
        memcpy(uncompressed_buff, (trustm_ec_key->public_key + trustm_ec_key->public_key_header_length + 3), uncompressed_buff_length);
    }

    else 
    {
        uncompressed_buff_length = trustm_ec_key->public_key[trustm_ec_key->public_key_header_length + 2] - 1;
        memcpy(uncompressed_buff, (trustm_ec_key->public_key + trustm_ec_key->public_key_header_length + 4), uncompressed_buff_length);
    }

    if ((group = EC_GROUP_new_by_curve_name(trustm_ecc_curve_to_nid(trustm_ec_key->key_curve))) == NULL
        || (point = EC_POINT_new(group)) == NULL
        || !EC_POINT_oct2point(group, point, uncompressed_buff, uncompressed_buff_length, NULL)
        || (x = BN_new()) == NULL
        || (y = BN_new()) == NULL
        || !EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        goto final;

    tolen = (EC_GROUP_order_bits(group) + 7) / 8;

    if (BN_bn2binpad(x, trustm_ec_key->x, tolen) != tolen)
        goto final;
    trustm_ec_key->point_x_buffer_length = tolen;

    if (BN_bn2binpad(y, trustm_ec_key->y, tolen) != tolen)
        goto final;
    trustm_ec_key->point_y_buffer_length = tolen;

    res = 1;

final:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return res;
}

// helper function to convert compressed form buffer to ecc points
int trustm_buffer_to_ecc_point(trustm_ec_key_t *trustm_ec_key, const unsigned char *buf, size_t len)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int tolen;
    int res = 0;

    if ((group = EC_GROUP_new_by_curve_name(trustm_ecc_curve_to_nid(trustm_ec_key->key_curve))) == NULL
        || (point = EC_POINT_new(group)) == NULL
        || !EC_POINT_oct2point(group, point, buf, len, NULL)
        || (x = BN_new()) == NULL
        || (y = BN_new()) == NULL
        || !EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        goto final;

    tolen = (EC_GROUP_order_bits(group) + 7) / 8;

    if (BN_bn2binpad(x, trustm_ec_key->x, tolen) != tolen)
        goto final;
    trustm_ec_key->point_x_buffer_length = tolen;

    if (BN_bn2binpad(y, trustm_ec_key->y, tolen) != tolen)
        goto final;
    trustm_ec_key->point_y_buffer_length = tolen;

    res = 1;

final:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return res;
}


// helper function to set uncompressed form buffer
int trustm_ec_point_to_uncompressed_buffer(trustm_ec_key_t *trustm_ec_key, void **buffer)
{
    size_t size;
    unsigned char *out;
    
    if (trustm_ec_key->point_x_buffer_length == 0 || trustm_ec_key->point_y_buffer_length == 0)
        return 0;
    
    size = 1 + trustm_ec_key->point_x_buffer_length + trustm_ec_key->point_y_buffer_length;
    
    *buffer = OPENSSL_malloc(size);
    if (*buffer == NULL)
        return 0;
        
    out = (unsigned char *) *buffer;
    
    *(out++) = 4; // uncompressed form
    memcpy(out, trustm_ec_key->x, trustm_ec_key->point_x_buffer_length);
    out += trustm_ec_key->point_x_buffer_length;
    memcpy(out, trustm_ec_key->y, trustm_ec_key->point_y_buffer_length);
    
    return size;
}

