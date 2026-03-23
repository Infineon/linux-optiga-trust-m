/*
 * SPDX-FileCopyrightText: 2025 Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <string.h>

#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_key_helper.h"

#define ASN1_INTEGER 0x02
#define ASN1_SEQUENCE 0x30

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

/* helpers to write DER length and TLV (supports lengths up to 4 bytes) */
static unsigned char *der_append_len(unsigned char *p, size_t len) {
    if (len < 0x80) {
        *p++ = (unsigned char)len;
    } else if (len <= 0xFF) {
        *p++ = 0x81; *p++ = (unsigned char)len;
    } else if (len <= 0xFFFF) {
        *p++ = 0x82; *p++ = (unsigned char)(len >> 8); *p++ = (unsigned char)len;
    } else if (len <= 0xFFFFFF) {
        *p++ = 0x83;
        *p++ = (unsigned char)(len >> 16); *p++ = (unsigned char)(len >> 8); *p++ = (unsigned char)len;
    } else {
        *p++ = 0x84;
        *p++ = (unsigned char)(len >> 24); *p++ = (unsigned char)(len >> 16);
        *p++ = (unsigned char)(len >> 8);  *p++ = (unsigned char)len;
    }
    return p;
}
static unsigned char *der_append_tlv(unsigned char *p, unsigned char tag,
                                     const unsigned char *val, size_t vlen) {
    *p++ = tag;
    p = der_append_len(p, vlen);
    if (vlen)
        memcpy(p, val, vlen);
    return p + vlen;
}

int trustm_ec_key_write(BIO *bout, trustm_ec_key_t *trustm_ec_key)
{
    int curve_nid;
    EVP_PKEY *pkey = NULL;
    unsigned char *privkey = NULL;
    unsigned char *bit_inner = NULL;
    unsigned char *oid_tlv = NULL;
    void* pub = NULL;
    size_t private_key_len = 0;
    int ret = 0;

    TRUSTM_PROVIDER_DBGFN(">");

    if (!bout || !trustm_ec_key) {
        return 0;
    }

    curve_nid = trustm_ecc_curve_to_nid(trustm_ec_key->key_curve);
    if (curve_nid == NID_undef) {
        return 0;
    }
    switch (curve_nid) {
        case NID_X9_62_prime256v1:
	      private_key_len = 32;
	      break;
        case NID_secp384r1:        
	      private_key_len = 48; 
	      break;
        case NID_secp521r1:        
	      private_key_len = 66; 
	      break;
        case NID_brainpoolP256r1:  
	      private_key_len = 32; 
	      break;
        case NID_brainpoolP384r1:  
	      private_key_len = 48; 
	      break;
        case NID_brainpoolP512r1:  
	      private_key_len = 64; 
	      break;
        default: 
	      return 0;
    }

    if (trustm_ec_key->point_x_buffer_length == 0 || trustm_ec_key->point_y_buffer_length == 0) {
        if (!trustm_buffer_to_ecc_point(trustm_ec_key, trustm_ec_key->public_key, trustm_ec_key->public_key_length)) {
            return 0;
        }
    }

    privkey = OPENSSL_zalloc(private_key_len);
    if (!privkey){
	    TRUSTM_PROVIDER_DBGFN("unable to alloc memory for dummy priv key");
        return 0;
    }
    uint16_t key_id = (uint16_t)trustm_ec_key->private_key_id;
    privkey[0] = (key_id >> 8) & 0xFF;
    privkey[1] = key_id & 0xFF;

    size_t publen = 1 + trustm_ec_key->point_x_buffer_length + trustm_ec_key->point_y_buffer_length;

    trustm_ec_point_to_uncompressed_buffer(trustm_ec_key,&pub);

    ASN1_OBJECT *ao = OBJ_nid2obj(curve_nid);
    if (!ao) {
	    TRUSTM_PROVIDER_DBGFN("unable to build asn1 object");
 	    goto error;
    }

    int oid_tlv_len = i2d_ASN1_OBJECT(ao, &oid_tlv); 
    if (oid_tlv_len <= 0 || !oid_tlv) {
	    TRUSTM_PROVIDER_DBGFN("failed to encode");
	    goto error;
    }
    size_t bit_inner_len = 1 + publen;
    bit_inner = OPENSSL_malloc(bit_inner_len);
    if (!bit_inner) goto error;
    bit_inner[0] = 0x00;
    memcpy(bit_inner + 1, pub, publen);

    unsigned char seq_content[2048]; 
    unsigned char *p = seq_content;

    unsigned char v1 = 1;
    p = der_append_tlv(p, ASN1_INTEGER, &v1, 1);
    p = der_append_tlv(p, 0x04, privkey, private_key_len);    
    p = der_append_tlv(p, 0xA0, oid_tlv, (size_t)oid_tlv_len);

    unsigned char bitstr_tlv[1024];
    unsigned char *bp = bitstr_tlv;
    bp = der_append_tlv(bp, 0x03, bit_inner, bit_inner_len);
    size_t bitstr_tlv_len = bp - bitstr_tlv;

    p = der_append_tlv(p, 0xA1, bitstr_tlv, bitstr_tlv_len);
    size_t seq_content_len = p - seq_content;

    unsigned char der[4096];
    unsigned char *dp = der;
    dp = der_append_tlv(dp, ASN1_SEQUENCE, seq_content, seq_content_len);
    size_t derlen = dp - der;

    const unsigned char *pp = der;
    pkey = d2i_AutoPrivateKey(NULL, &pp, (long)derlen);
    if (!pkey) {
        goto error;
    }

    if (!PEM_write_bio_PrivateKey(bout, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto error;
    }

    ret = 1;
    TRUSTM_PROVIDER_DBGFN("<");

error:
    if (pkey) EVP_PKEY_free(pkey);
    if (bit_inner) OPENSSL_free(bit_inner);
    if (pub) OPENSSL_free(pub);
    if (privkey) OPENSSL_free(privkey);
    if (oid_tlv) OPENSSL_free(oid_tlv);
    return ret;
}

int trustm_rsa_key_write(BIO *bout, trustm_rsa_key_t *trustm_rsa_key)
{
    TRUSTM_PROVIDER_DBGFN(">");
    if (!bout || !trustm_rsa_key || trustm_rsa_key->modulus_length == 0)
        return 0;

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char seq_content[4096];
    unsigned char *p = seq_content;

    unsigned char version = 0x00;
    p = der_append_tlv(p, ASN1_INTEGER, &version, 1);

    p = der_append_tlv(p, ASN1_INTEGER, trustm_rsa_key->modulus, trustm_rsa_key->modulus_length);

    unsigned char exp_bytes[3] = {0x01, 0x00, 0x01};
    p = der_append_tlv(p, ASN1_INTEGER, exp_bytes, sizeof(exp_bytes));

    unsigned char priv_exponent[1] = {0x00};
    unsigned char prime1[1] = {0x01};
    
    uint8_t prime2[2];
    prime2[0] = (trustm_rsa_key->private_key_id >> 8) & 0xFF; // high byte
    prime2[1] = trustm_rsa_key->private_key_id & 0xFF;        // low byte
    
    unsigned char exponent1[1] = {0x00};
    unsigned char exponent2[1] = {0x00};
    unsigned char coefficient[4] = {0};

    p = der_append_tlv(p, ASN1_INTEGER, priv_exponent, sizeof(priv_exponent));
    p = der_append_tlv(p, ASN1_INTEGER, prime1, sizeof(prime1));
    p = der_append_tlv(p, ASN1_INTEGER, prime2, sizeof(prime2));
    p = der_append_tlv(p, ASN1_INTEGER, exponent1, sizeof(exponent1));
    p = der_append_tlv(p, ASN1_INTEGER, exponent2, sizeof(exponent2));
    p = der_append_tlv(p, ASN1_INTEGER, coefficient, sizeof(coefficient));

    size_t seq_len = p - seq_content;
    unsigned char *der = malloc(seq_len + 16);
    if (!der)
        goto error;
    p = der_append_tlv(der, ASN1_SEQUENCE, seq_content, seq_len);

    const unsigned char *der_ptr = der;
    pkey = d2i_AutoPrivateKey(NULL, &der_ptr, (long)(p - der));
    if (pkey && PEM_write_bio_PrivateKey(bout, pkey, NULL, NULL, 0, NULL, NULL)){
        ret = 1;
    }
	TRUSTM_PROVIDER_DBGFN("<");
error:
    if (pkey) EVP_PKEY_free(pkey);
    if (der) free(der);
    return ret;
}
