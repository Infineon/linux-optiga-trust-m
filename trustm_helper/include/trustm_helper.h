/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
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
#include "sys/types.h"
#include "unistd.h"
#include <signal.h>
#include <time.h>
#include <errno.h>   

//Debug Print
//#define DEBUG_TRUSTM_HELPER =1
//#define HIBERNATE_ENABLE =1

#ifdef DEBUG_TRUSTM_HELPER

#define TRUSTM_HELPER_DBG(x, ...)      fprintf(stderr, "%d:%s:%d " x "\n", getpid(),__FILE__, __LINE__, ##__VA_ARGS__)
#define TRUSTM_HELPER_DBGFN(x, ...)    fprintf(stderr, "%d:%s:%d %s: " x "\n", getpid(),__FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define TRUSTM_HELPER_DBG(x, ...)
#define TRUSTM_HELPER_DBGFN(x, ...)
#endif

#define TRUSTM_HELPER_INFO(...)    printf(__VA_ARGS__)
#define TRUSTM_HELPER_ERRFN(x, ...)    fprintf(stderr, "%d:Error in %s:%d %s: " x "\n",getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_HELPER_RETCODEFN(y, x, ...)   fprintf(stdout, "\n%d:Error [0x%.4X] : " x "\n",getpid(), y, ##__VA_ARGS__)

#define TRUSTM_CTX_FILENAME             ".trustm_ctx"
#define TRUSTM_HIBERNATE_CTX_FILENAME   ".trustm_hibernate_ctx"
#define BUSY_WAIT_TIME_OUT 6000 // Note: This value must be at least 4000, any value smaller might encounter premature exit while waiting response from Trust M
#define MAX_RSA_KEY_GEN_TIME 62000 // Note: RSA key gen time can very from 7s to 60s

// ********** typedef
typedef struct _tag_trustm_UID {
    uint8_t bCimIdentifer;
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
    CREATION    = 0x01,
    INITIALIZATION  = 0x03,
    OPERATION   = 0x07,
    TERMINATION = 0x0f
} trustm_eLifeCycStatus_t;

typedef struct trustm_metadata_str
{
  uint8_t metadataLen;
  uint8_t C0_lsc0;
  uint8_t C1_verion[2];
  uint16_t C4_maxSize;
  uint16_t C5_used;
  uint8_t D0_change[10];
  uint8_t D0_changeLen;
  uint8_t D1_read[10];
  uint8_t D1_readLen;
  uint8_t D3_execute[10];
  uint8_t D3_executeLen;
  uint8_t E0_algo;
  uint8_t E1_keyUsage;
  uint8_t E8_dataObjType;  
} trustm_metadata_t;


// *********** Extern
extern optiga_util_t * me_util;
extern optiga_crypt_t * me_crypt;
extern optiga_lib_status_t optiga_lib_status;
extern uint16_t trustm_open_flag;
extern uint8_t trustm_hibernate_flag;

// Function Prototype
optiga_lib_status_t _trustm_Open(void);
optiga_lib_status_t trustm_Close(void);
optiga_lib_status_t trustm_Open(void);
optiga_lib_status_t trustm_WaitForCompletion(uint16_t wait_time);
void optiga_util_callback(void * context, optiga_lib_status_t return_status);
void optiga_crypt_callback(void * context, optiga_lib_status_t return_status);

void trustmHexDump(uint8_t *pdata, uint32_t len);
uint16_t trustmWritePEM(uint8_t *buf, uint32_t len, const char *filename, char *name);
uint16_t trustmWriteDER(uint8_t *buf, uint32_t len, const char *filename);

uint16_t trustmReadPEM(uint8_t *buf, uint32_t *len, const char *filename, char *name, uint16_t *keySize, uint16_t *keyType);
uint16_t trustmReadDER(uint8_t *buf, uint32_t *len, const char *filename);

void trustmdecodeMetaData(uint8_t * metaData);
uint16_t trustmWriteX509PEM(X509 *x509, const char *filename);
uint16_t trustmReadX509PEM(X509 **x509, const char *filename);

void trustmPrintErrorCode(uint16_t errcode);
void trustmGetOIDName(uint16_t optiga_oid, char *name);

optiga_lib_status_t trustm_readUID(utrustm_UID_t *UID);
optiga_lib_status_t trustmReadMetadata(uint16_t optiga_oid, trustm_metadata_t *oidMetadata);

uint32_t trustmHexorDec(const char *aArg);
uint16_t trustmwriteTo(uint8_t *buf, uint32_t len, const char *filename);
uint16_t trustmreadFrom(uint8_t *data, uint8_t *filename);

#endif  // _TRUSTM_HELPER_H_
