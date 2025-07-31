#include <string.h>
#include <math.h>


#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>

#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

#include "trustm_helper.h"
#include "trustm_provider_common.h"
#include "trustm_ec_key_helper.h"

typedef struct trustm_encoder_ctx_str {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
} trustm_encoder_ctx_t;


/* RSA PUBLIC KEY */

typedef struct {
    ASN1_INTEGER *n;
    ASN1_INTEGER *e;
} TRUSTM_RSA_PUBKEY;

ASN1_SEQUENCE(TRUSTM_RSA_PUBKEY) = {
    ASN1_SIMPLE(TRUSTM_RSA_PUBKEY, n, ASN1_INTEGER),
    ASN1_SIMPLE(TRUSTM_RSA_PUBKEY, e, ASN1_INTEGER)
}  ASN1_SEQUENCE_END(TRUSTM_RSA_PUBKEY)

IMPLEMENT_ASN1_FUNCTIONS(TRUSTM_RSA_PUBKEY);
IMPLEMENT_PEM_write_bio(TRUSTM_RSA_PUBKEY, TRUSTM_RSA_PUBKEY, PEM_STRING_RSA_PUBLIC, TRUSTM_RSA_PUBKEY);


static TRUSTM_RSA_PUBKEY *trustm_get_rsa_pubkey(const trustm_rsa_key_t *pkey)
{
    TRUSTM_RSA_PUBKEY *rsa_pubkey;
    BIGNUM *nbig;
    uint32_t exponent;
    uint8_t modulus_buffer[300];
    uint16_t modulus_length;
    TRUSTM_PROVIDER_DBGFN(">");
    rsa_pubkey = TRUSTM_RSA_PUBKEY_new();
    if (rsa_pubkey == NULL)
        return NULL;

    /* extracting modulus from trustm rsa public key struct */
    if (pkey->key_size == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL)
    {
        modulus_length = pkey->public_key[pkey->public_key_header_length + 9]; // get the total length in bytes of modulus
        memcpy(modulus_buffer, (pkey->public_key + pkey->public_key_header_length + 10), modulus_length);
    }
    else 
    {
        modulus_length = (pkey->public_key[pkey->public_key_header_length + 11]) << 8 | 
                                    (pkey->public_key[pkey->public_key_header_length + 12]); // get the total length in bytes of modulus

        memcpy(modulus_buffer, (pkey->public_key + pkey->public_key_header_length + 13), modulus_length);
    }

    /* set n */
    nbig = BN_bin2bn(modulus_buffer, modulus_length, NULL);
    if (nbig == NULL || !BN_to_ASN1_INTEGER(nbig, rsa_pubkey->n))
    {
        TRUSTM_RSA_PUBKEY_free(rsa_pubkey);
        return NULL;
    }

    BN_free(nbig);

    /* set e */
    exponent = pkey->exponent;
    if (exponent != 0x10001)
        exponent = 0x10001;

    if (!ASN1_INTEGER_set(rsa_pubkey->e, exponent))
    {
        TRUSTM_RSA_PUBKEY_free(rsa_pubkey);
        return NULL;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return rsa_pubkey;
}


int trustm_get_rsa_pubkey_der(const trustm_rsa_key_t *pkey, unsigned char **penc)
{
    TRUSTM_RSA_PUBKEY *rsa_pubkey;
    int penclen;
    TRUSTM_PROVIDER_DBGFN(">");
    rsa_pubkey = trustm_get_rsa_pubkey(pkey);
    if (rsa_pubkey == NULL)
        return -1;

    /* export as DER */
    penclen = i2d_TRUSTM_RSA_PUBKEY(rsa_pubkey, penc);
    TRUSTM_RSA_PUBKEY_free(rsa_pubkey);
    TRUSTM_PROVIDER_DBGFN("<");
    return penclen;
}


static X509_PUBKEY * trustm_get_x509_rsa_pubkey(const trustm_rsa_key_t *pkey)
{
    unsigned char *penc = NULL;
    int penclen;
    X509_PUBKEY *pubkey;
    TRUSTM_PROVIDER_DBGFN(">");
    penclen = trustm_get_rsa_pubkey_der(pkey, &penc);
    if (penclen < 0)
        return NULL;

    pubkey = X509_PUBKEY_new();
    if (pubkey == NULL)
    {
        free(penc);
        return NULL;
    }

    /* per RFC3279 the parameters must be NULL */
    X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL, penc, penclen);
    TRUSTM_PROVIDER_DBGFN("<");
    return pubkey;
}



static OSSL_FUNC_encoder_newctx_fn trustm_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn trustm_encoder_freectx;



static void *trustm_encoder_newctx(void *provctx)
{
    trustm_ctx_t *trustm_ctx = provctx;
    trustm_encoder_ctx_t *trustm_encoder_ctx = OPENSSL_zalloc(sizeof(trustm_encoder_ctx_t));
    TRUSTM_PROVIDER_DBGFN(">");
    if (trustm_encoder_ctx == NULL)
        return NULL;

    trustm_encoder_ctx->core = trustm_ctx->core;
    trustm_encoder_ctx->libctx = trustm_ctx->libctx;
    TRUSTM_PROVIDER_DBGFN("<");
    return trustm_encoder_ctx;
}


static void trustm_encoder_freectx(void *ctx)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;

    if (trustm_encoder_ctx == NULL)
        return;

    OPENSSL_clear_free(trustm_encoder_ctx, sizeof(trustm_encoder_ctx_t));
}

/* numer of bytes/octets per line */
#define TEXT_ENCODE_OCTETS_PER_LINE 16

static OSSL_FUNC_encoder_encode_fn trustm_rsa_encoder_encode_text;
static int trustm_rsa_encoder_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    const trustm_rsa_key_t *trustm_rsa_key = key;
    BIO *bout;
    int i;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    BIO_printf(bout, "---- OPTIGA TrustM ----\nRSA Key Length: %d bit\n", (trustm_rsa_key->key_size == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL ? 1024 : 2048));
    BIO_printf(bout, "Private key OID: 0x%.4X\n", (trustm_rsa_key->private_key_id));
    BIO_printf(bout, "Key Usage: 0x%.2X\n", (trustm_rsa_key->key_usage));
    BIO_printf(bout, "Public Key Content:");

    for (i = 0; i < trustm_rsa_key->public_key_length; i++)
    {
        if ((i % TEXT_ENCODE_OCTETS_PER_LINE) == 0)
            BIO_printf(bout, "\n");

        BIO_printf(bout, "%.2X ", trustm_rsa_key->public_key[i]);
    }

    BIO_printf(bout, "\n");
    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

const OSSL_DISPATCH trustm_rsa_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_rsa_encoder_encode_text },
    { 0, NULL }
};

///////////////////////////////////////////////////////////////////////////////////////
static int trustm_rsa_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_rsa_key_t *trustm_rsa_key)
{
    X509_PUBKEY *pubkey;
    int ret;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((pubkey = trustm_get_x509_rsa_pubkey(trustm_rsa_key)) == NULL)
        return 0;

    ret = PEM_write_bio_X509_PUBKEY(bout, pubkey);
    X509_PUBKEY_free(pubkey);
    return ret;
    TRUSTM_PROVIDER_DBGFN("<");
}

static OSSL_FUNC_encoder_encode_fn trustm_rsa_encoder_encode_SubjectPublicKeyInfo_pem;
static int trustm_rsa_encoder_encode_SubjectPublicKeyInfo_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_rsa_key_t *trustm_rsa_key = (trustm_rsa_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_rsa_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx, bout, trustm_rsa_key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ret = trustm_rsa_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx, bout, trustm_rsa_key);

    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}


static OSSL_FUNC_encoder_does_selection_fn trustm_rsa_encoder_SubjectPublicKeyInfo_pem_does_selection;
static int trustm_rsa_encoder_SubjectPublicKeyInfo_pem_does_selection(void *ctx, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    
    return 0;
}


const OSSL_DISPATCH trustm_rsa_encoder_SubjectPublicKeyInfo_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_rsa_encoder_SubjectPublicKeyInfo_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_rsa_encoder_encode_SubjectPublicKeyInfo_pem},
    { 0, NULL }
};
///////////////////////////////////////////////////////////////////////////////////////


static int trustm_rsa_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_rsa_key_t *trustm_rsa_key)
{
    X509_PUBKEY *pubkey;
    int ret;

    TRUSTM_PROVIDER_DBGFN(">");
    if ((pubkey = trustm_get_x509_rsa_pubkey(trustm_rsa_key)) == NULL)
        return 0;
    
    ret = i2d_X509_PUBKEY_bio(bout, pubkey);
    X509_PUBKEY_free(pubkey);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_encode_fn trustm_rsa_encoder_encode_SubjectPublicKeyInfo_der;
static int trustm_rsa_encoder_encode_SubjectPublicKeyInfo_der(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_rsa_key_t *trustm_rsa_key = (trustm_rsa_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_rsa_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx, bout, trustm_rsa_key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ret = trustm_rsa_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx, bout, trustm_rsa_key);

    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}


static OSSL_FUNC_encoder_does_selection_fn trustm_rsa_encoder_SubjectPublicKeyInfo_der_does_selection;
static int trustm_rsa_encoder_SubjectPublicKeyInfo_der_does_selection(void *ctx, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    
    return 0;
}

const OSSL_DISPATCH trustm_rsa_encoder_SubjectPublicKeyInfo_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_rsa_encoder_SubjectPublicKeyInfo_der_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_rsa_encoder_encode_SubjectPublicKeyInfo_der},
    { 0, NULL }
};

///////////////////////////////////////////////////////////////////////////////////
static int trustm_rsa_encode_public_pkcs1_pem(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_rsa_key_t *trustm_rsa_key)
{
    TRUSTM_RSA_PUBKEY *tpk;
    int ret;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((tpk = trustm_get_rsa_pubkey(trustm_rsa_key)) == NULL)
        return 0;

    ret = PEM_write_bio_TRUSTM_RSA_PUBKEY(bout, tpk);

    TRUSTM_RSA_PUBKEY_free(tpk);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_encode_fn trustm_rsa_encoder_encode_pkcs1_pem;
static int trustm_rsa_encoder_encode_pkcs1_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_rsa_key_t *trustm_rsa_key = (trustm_rsa_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_rsa_encode_public_pkcs1_pem(trustm_encoder_ctx, bout, trustm_rsa_key);


    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_rsa_encoder_pkcs1_pem_does_selection;
static int trustm_rsa_encoder_pkcs1_pem_does_selection(void *ctx, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    
    return 0;
}


const OSSL_DISPATCH trustm_rsa_encoder_pkcs1_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_rsa_encoder_pkcs1_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_rsa_encoder_encode_pkcs1_pem},
    { 0, NULL }
};

///////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////
static int trustm_rsa_encode_public_pkcs1_der(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_rsa_key_t *trustm_rsa_key)
{
    TRUSTM_RSA_PUBKEY *tpk;
    int ret;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((tpk = trustm_get_rsa_pubkey(trustm_rsa_key)) == NULL)
        return 0;

    ret = ASN1_item_i2d_bio(ASN1_ITEM_rptr(TRUSTM_RSA_PUBKEY), bout, tpk);

    TRUSTM_RSA_PUBKEY_free(tpk);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}


static OSSL_FUNC_encoder_encode_fn trustm_rsa_encoder_encode_pkcs1_der;
static int trustm_rsa_encoder_encode_pkcs1_der(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_rsa_key_t *trustm_rsa_key = (trustm_rsa_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_rsa_encode_public_pkcs1_der(trustm_encoder_ctx, bout, trustm_rsa_key);


    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_rsa_encoder_pkcs1_der_does_selection;
static int trustm_rsa_encoder_pkcs1_der_does_selection(void *ctx, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    
    return 0;
}


const OSSL_DISPATCH trustm_rsa_encoder_pkcs1_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_rsa_encoder_pkcs1_der_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_rsa_encoder_encode_pkcs1_der},
    { 0, NULL }
};


/* EC PUBLIC KEY ENCODERS */
static X509_PUBKEY *trustm_get_x509_ec_pubkey(trustm_ec_key_t *pkey)
{
    X509_PUBKEY *pubkey;
    unsigned char *penc = NULL;
    int penclen;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((pubkey = X509_PUBKEY_new()) == NULL)
        return NULL;

    penclen = trustm_ec_point_to_uncompressed_buffer(pkey, (void **)&penc);
    if (penclen == 0)
    {
        X509_PUBKEY_free(pubkey);
        OPENSSL_free(penc);
        return NULL;
    }

    if (!X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), V_ASN1_OBJECT, OBJ_nid2obj(trustm_ecc_curve_to_nid(pkey->key_curve)),
                        penc, penclen))
    {
        OPENSSL_free(penc);
        return NULL;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    return pubkey;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
static int trustm_ec_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_ec_key_t *trustm_ec_key)
{
    X509_PUBKEY *pubkey;
    int ret;
    TRUSTM_PROVIDER_DBGFN(">");
    if ((pubkey = trustm_get_x509_ec_pubkey(trustm_ec_key)) == NULL)
        return 0;

    ret = PEM_write_bio_X509_PUBKEY(bout, pubkey);
    X509_PUBKEY_free(pubkey);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_encode_fn trustm_ec_encoder_encode_SubjectPublicKeyInfo_pem;
static int trustm_ec_encoder_encode_SubjectPublicKeyInfo_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_ec_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx, bout, trustm_ec_key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ret = trustm_ec_encode_public_SubjectPublicKeyInfo_pem(trustm_encoder_ctx, bout, trustm_ec_key);

    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}


static OSSL_FUNC_encoder_does_selection_fn trustm_ec_encoder_SubjectPublicKeyInfo_pem_does_selection;
static int trustm_ec_encoder_SubjectPublicKeyInfo_pem_does_selection(void *ctx, int selection)
{
    TRUSTM_PROVIDER_DBGFN(">");
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    TRUSTM_PROVIDER_DBGFN("<");
    return 0;
}


const OSSL_DISPATCH trustm_ec_encoder_SubjectPublicKeyInfo_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_ec_encoder_SubjectPublicKeyInfo_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_ec_encoder_encode_SubjectPublicKeyInfo_pem},
    { 0, NULL }
};

//////////////////////////////////////////////////////////////////////////////////////////


static int trustm_ec_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx_t *trustm_encoder_ctx, BIO *bout, trustm_ec_key_t *trustm_ec_key)
{
    X509_PUBKEY *pubkey;
    int ret;
    TRUSTM_PROVIDER_DBGFN(">");

    if ((pubkey = trustm_get_x509_ec_pubkey(trustm_ec_key)) == NULL)
        return 0;
    
    ret = i2d_X509_PUBKEY_bio(bout, pubkey);
    X509_PUBKEY_free(pubkey);
    TRUSTM_PROVIDER_DBGFN("<");
    
    return ret;
}

static OSSL_FUNC_encoder_encode_fn trustm_ec_encoder_encode_SubjectPublicKeyInfo_der;
static int trustm_ec_encoder_encode_SubjectPublicKeyInfo_der(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");

    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ret = trustm_ec_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx, bout, trustm_ec_key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ret = trustm_ec_encode_public_SubjectPublicKeyInfo_der(trustm_encoder_ctx, bout, trustm_ec_key);


    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}


static OSSL_FUNC_encoder_does_selection_fn trustm_ec_encoder_SubjectPublicKeyInfo_der_does_selection;
static int trustm_ec_encoder_SubjectPublicKeyInfo_der_does_selection(void *ctx, int selection)
{
    TRUSTM_PROVIDER_DBGFN(">");
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
    TRUSTM_PROVIDER_DBGFN("<");
    return 0;
}

const OSSL_DISPATCH trustm_ec_encoder_SubjectPublicKeyInfo_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_ec_encoder_SubjectPublicKeyInfo_der_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_ec_encoder_encode_SubjectPublicKeyInfo_der},
    { 0, NULL }
};

//////////////////////////////////////////////////////////////////////////////////////////////////

static int trustm_ec_encoder_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], 
                                            int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *ectx = ctx;
    trustm_ec_key_t *pkey = (trustm_ec_key_t *) key;
    BIO *bout;
    int curve_nid;
    size_t size;
    void *buffer;
    uint8_t *pubkey_buffer;
    int i;
    TRUSTM_PROVIDER_DBGFN(">");
    bout = BIO_new_from_core_bio(ectx->libctx, cout);
    if (bout == NULL)
        return 0;

    curve_nid = trustm_ecc_curve_to_nid(pkey->key_curve);
    BIO_printf(bout, "Trust M ECC Key - Algorithm  %s\n", EC_curve_nid2nist(curve_nid));

    size = trustm_ec_point_to_uncompressed_buffer(pkey, (void **)&buffer);

    pubkey_buffer = OPENSSL_zalloc(sizeof (char));
    memcpy(pubkey_buffer, buffer, size);

    BIO_printf(bout, "\npub:");
    for (i = 0; i < size; i++)
    {
        if ((i % TEXT_ENCODE_OCTETS_PER_LINE) == 0)
            BIO_printf(bout, "\n");

        BIO_printf(bout, "%.2X ", pubkey_buffer[i]);
    }

    BIO_printf(bout, "\nASN1 OID: %s\n", OBJ_nid2sn(curve_nid));

    OPENSSL_free(buffer);
    OPENSSL_free(pubkey_buffer);
    BIO_free(bout);
    return 1;
}

const OSSL_DISPATCH trustm_ec_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_ec_encoder_encode_text },
    { 0, NULL }
};


//~ static int trustm_key_write(trustm_encoder_ctx_t *ctx, BIO *bout, trustm_ec_key_t *trustm_ec_key) 
//~ {
   //~ //To do: Generate key.pem using OpenSSL 3.0 API  
//~ }

//Generate Key.pem using deprecated openssl 1.1 API for testing purpose at this moment
static int trustm_key_write(trustm_encoder_ctx_t *ctx, BIO *bout, trustm_ec_key_t *trustm_ec_key) 
{
    int curve_nid;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *priv_bn = NULL;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *privkey = NULL;
    size_t private_key_len                  = sizeof(privkey);
    int ret = 0;
    
    TRUSTM_PROVIDER_DBGFN(">");
    if (!ctx || !bout || !trustm_ec_key) {
        TRUSTM_PROVIDER_DBGFN("Error: Invalid inputs");
        goto err;
    }
    curve_nid = trustm_ecc_curve_to_nid(trustm_ec_key->key_curve);
    if (curve_nid == NID_undef) {
        TRUSTM_PROVIDER_DBGFN("Error: Invalid curve NID");
        return 0;
    }
    switch (curve_nid) {
        case NID_X9_62_prime256v1: /* P-256 */
            private_key_len = 32;
            break;            
        case NID_secp384r1: /* P-384 */
            private_key_len = 48;
            break;
        case NID_secp521r1: /* P-521 */
            private_key_len = 66;
            break;
        case NID_brainpoolP256r1: /* Brainpool 256 */
            private_key_len = 32;
            break;
        case NID_brainpoolP384r1: /* Brainpool 384 */
            private_key_len = 48;
            break;
        case NID_brainpoolP512r1: /* Brainpool 512 */
            private_key_len = 64;
            break;            
        default:
            TRUSTM_PROVIDER_DBGFN("Error: Unsupported curve");
            return 0;
    }   
    ec_key = EC_KEY_new_by_curve_name(curve_nid); 
    if (!ec_key) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create EC_KEY");
        goto err;
    }
    x = BN_bin2bn(trustm_ec_key->x, trustm_ec_key->point_x_buffer_length, NULL);
    y = BN_bin2bn(trustm_ec_key->y, trustm_ec_key->point_y_buffer_length, NULL);
    if (!x || !y) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create BIGNUMs for x, y coordinates");
        goto err;
    }
    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to set public key coordinates");
        goto err;
    }
     privkey = OPENSSL_zalloc(private_key_len);
     uint16_t key_id = (uint16_t)trustm_ec_key->private_key_id;
     privkey[0] = (key_id >> 8) & 0xFF; // High byte
     privkey[1] = key_id & 0xFF;        // Low byte
     
    priv_bn = BN_bin2bn(privkey, private_key_len, NULL);
    if (!priv_bn) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create BIGNUM for private key");
        goto err;
    }
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to set private key");
        goto err;
    }
    pkey = EVP_PKEY_new();
    if (!pkey) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create EVP_PKEY");
        goto err;
    }
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to assign EC_KEY to EVP_PKEY");
        EVP_PKEY_free(pkey);
        goto err;
    }
    ec_key = NULL; 
    if (!PEM_write_bio_PrivateKey(bout, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto err;
    }
    ret = 1;

err:
    BN_free(priv_bn);
    OPENSSL_free(privkey);
    EVP_PKEY_free(pkey);
    return ret;
}

// exporting private key ID into key.pem
//////////////////////////////////////////////////////////////////////////////////
static OSSL_FUNC_encoder_encode_fn trustm_encode_SubjectPrivateKeyInfo_pem;
static int trustm_encode_SubjectPrivateKeyInfo_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");

    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;
    ret = trustm_key_write(trustm_encoder_ctx, bout, trustm_ec_key);
    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_encoder_SubjectPrivateKeyInfo_pem_does_selection;
static int trustm_encoder_SubjectPrivateKeyInfo_pem_does_selection(void *ctx, int selection)
{
    TRUSTM_PROVIDER_DBGFN(">");
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    TRUSTM_PROVIDER_DBGFN("<");
    return 0;
}

const OSSL_DISPATCH trustm_encoder_SubjectPrivateKeyInfo_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_encoder_SubjectPrivateKeyInfo_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_encode_SubjectPrivateKeyInfo_pem},
    { 0, NULL }
};

static OSSL_FUNC_encoder_encode_fn trustm_encode_SubjectPrivateKeyInfo_der;
static int trustm_encode_SubjectPrivateKeyInfo_der(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return 1;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_encoder_SubjectPrivateKeyInfo_der_does_selection;
static int trustm_encoder_SubjectPrivateKeyInfo_der_does_selection(void *ctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    
    return 0;
}

const OSSL_DISPATCH trustm_encoder_SubjectPrivateKeyInfo_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_encoder_SubjectPrivateKeyInfo_der_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_encode_SubjectPrivateKeyInfo_der},
    { 0, NULL }
};
////////////////////////// dummy private key encoders ///////////////////////////////
