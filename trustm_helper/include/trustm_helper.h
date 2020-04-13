/**
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE

*/
#ifndef _TRUSTM_HELPER_H_
#define _TRUSTX_HELPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "ifx_i2c_config.h"
#include "optiga_util.h"
#include "optiga_comms.h"
#include "optiga_crypt.h"

//Debug Print
//#define DEBUG_TRUSTM_HELPER =1

#ifdef DEBUG_TRUSTM_HELPER

#define TRUSTM_HELPER_DBG(x, ...)      fprintf(stderr, x,##__VA_ARGS__)
#define TRUSTM_HELPER_DBGFN(x, ...)    fprintf(stderr, "%s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_HELPER_ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#else

#define TRUSTM_HELPER_DBG(x, ...)
#define TRUSTM_HELPER_DBGFN(x, ...)
#define TRUSTM_HELPER_ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif

// ********** typedef
typedef struct _tag_trustm_UID {
	uint8_t	bCimIdentifer;
	uint8_t bPlatformIdentifier;
	uint8_t bModelIdentifier;
	uint8_t wROMCode[2];
	uint8_t rgbChipType[6];
	uint8_t rgbBatchNumber[6];
	uint8_t wChipPositionX[2];
	uint8_t wChipPositionY[2];
	uint8_t dwFirmwareIdentifier[4];
	uint8_t rgbESWBuild[2];
} trustm_UID_t;

typedef union _tag_utrustm_UID {
	uint8_t b[27];
	trustm_UID_t st;
} utrustm_UID_t;

typedef enum _tag_trustm_LifeCycStatus {
	CREATION 	= 0x01,
	INITIALIZATION 	= 0x03,
	OPERATION	= 0x07,
	TERMINATION	= 0x0f
} trustm_eLifeCycStatus_t;


// *********** Extern
extern optiga_util_t * me_util;
extern optiga_crypt_t * me_crypt;
extern optiga_lib_status_t optiga_lib_status;

// Function Prototype
optiga_lib_status_t trustm_Open(void);
optiga_lib_status_t trustm_Close(void);
void optiga_crypt_callback(void * context, optiga_lib_status_t return_status);

void trustmHexDump(uint8_t *pdata, uint32_t len);
uint16_t trustmWritePEM(uint8_t *buf, uint32_t len, const char *filename, char *name);
uint16_t trustmWriteDER(uint8_t *buf, uint32_t len, const char *filename);
uint16_t trustmReadPEM(uint8_t *buf, uint32_t *len, const char *filename, char *name);
uint16_t trustmReadDER(uint8_t *buf, uint32_t *len, const char *filename);
void trustmdecodeMetaData(uint8_t * metaData);
uint16_t trustmWriteX509PEM(X509 *x509, const char *filename);
uint16_t trustmReadX509PEM(X509 **x509, const char *filename);

optiga_lib_status_t trustm_readUID(utrustm_UID_t *UID);

#endif	// _TRUSTM_HELPER_H_
