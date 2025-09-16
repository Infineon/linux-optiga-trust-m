/*
 * SPDX-FileCopyrightText: 2025 Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _TRUSTM_EC_KEY_HELPER_
#define _TRUSTM_EC_KEY_HELPER_


#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


#include "trustm_provider_common.h"
#include "trustm_helper.h"


//
int trustm_ecc_curve_to_nid(optiga_ecc_curve_t curve);
optiga_ecc_curve_t trustm_nid_to_ecc_curve(int nid);
int trustm_ecc_public_key_to_point(trustm_ec_key_t *trustm_ec_key);
int trustm_buffer_to_ecc_point(trustm_ec_key_t *trustm_ec_key, const unsigned char *buf, size_t len);
// helper function to set uncompressed form buffer
int trustm_ec_point_to_uncompressed_buffer(trustm_ec_key_t *trustm_ec_key, void **buffer);

int trustm_ec_key_write(BIO *bout, trustm_ec_key_t *trustm_ec_key);
int trustm_rsa_key_write(BIO *bout, trustm_rsa_key_t *trustm_rsa_key);



#endif
