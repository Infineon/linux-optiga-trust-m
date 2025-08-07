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
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
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
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;
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
    TRUSTM_PROVIDER_DBGFN("<");
    return 1;
}

const OSSL_DISPATCH trustm_ec_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_ec_encoder_encode_text },
    { 0, NULL }
};

// exporting private key ID into key.pem
//////////////////////////////////////////////////////////////////////////////////
static OSSL_FUNC_encoder_encode_fn trustm_encode_PrivateKeyInfo_pem;
static int trustm_encode_PrivateKeyInfo_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    trustm_encoder_ctx_t *trustm_encoder_ctx = ctx;
    trustm_ec_key_t *trustm_ec_key = (trustm_ec_key_t *) key;
    BIO *bout;
    int ret = 0;
    TRUSTM_PROVIDER_DBGFN(">");

    TRUSTM_PROVIDER_DBGFN("selection: %d (0x%X)", selection, selection); 
    bout = BIO_new_from_core_bio(trustm_encoder_ctx->libctx, cout);
    if (bout == NULL)
        return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        ret = trustm_key_write(bout, trustm_ec_key);
    }
    BIO_free(bout);
    TRUSTM_PROVIDER_DBGFN("<");
    return ret;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_encoder_PrivateKeyInfo_pem_does_selection;
static int trustm_encoder_PrivateKeyInfo_pem_does_selection(void *ctx, int selection)
{
    TRUSTM_PROVIDER_DBGFN("selection: %d (0x%X)", selection, selection); 
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    return 0;
}

const OSSL_DISPATCH trustm_encoder_PrivateKeyInfo_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_encoder_PrivateKeyInfo_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_encode_PrivateKeyInfo_pem},
    { 0, NULL }
};

static OSSL_FUNC_encoder_encode_fn trustm_encode_PrivateKeyInfo_der;
static int trustm_encode_PrivateKeyInfo_der(void *ctx, OSSL_CORE_BIO *cout, const void *key, 
                                            const OSSL_PARAM key_abstract[], int selection, 
                                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return 1;
}

static OSSL_FUNC_encoder_does_selection_fn trustm_encoder_PrivateKeyInfo_der_does_selection;
static int trustm_encoder_PrivateKeyInfo_der_does_selection(void *ctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    
    return 0;
}

const OSSL_DISPATCH trustm_encoder_PrivateKeyInfo_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void(*)(void))trustm_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void(*)(void))trustm_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))trustm_encoder_PrivateKeyInfo_der_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))trustm_encode_PrivateKeyInfo_der},
    { 0, NULL }
};
////////////////////////// dummy private key encoders ///////////////////////////////
