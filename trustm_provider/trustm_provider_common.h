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
#ifndef _TRUSTM_ENGINE_COMMON_H_
#define _TRUSTM_ENGINE_COMMON_H_

#include <stdio.h>
#include <pthread.h>
#include <openssl/core.h>

#include "optiga_lib_common.h"
#include "trustm_helper.h"
#include "trustm_helper_ipc_lock.h"

#include "sys/types.h"
#include "unistd.h"
#include <signal.h>
#include <time.h>
#include <errno.h>   

// SETTINGS
#define OBJ_MAX_LEN          (128) /* Maximum length for key object paths or passwords */
#define KEY_CONTEXT_MAX_LEN  (100)
#define PARAM_MAX_LEN        (128)

#define WORKAROUND 1
#define TRUSTM_RAND_ENABLED 
//~ #define TRUSTM_ENGINE_DEBUG 
//~ #define TRUST_ENG_CLOSE_APP_ENABLE

#ifdef WORKAROUND
#define TRUSTM_WORKAROUND_TIMER_ARM        pal_os_event_arm()
#define TRUSTM_WORKAROUND_TIMER_DISARM     pal_os_event_disarm()
#define TRUSTM_WORKAROUND_TIMER_DESTROY    pal_os_event_destroy1()
#else
#define TRUSTM_WORKAROUND_TIMER_ARM
#define TRUSTM_WORKAROUND_TIMER_DISARM
#define TRUSTM_WORKAROUND_TIMER_DESTROY    
#endif

#ifdef TRUSTM_ENGINE_DEBUG

#define TRUSTM_ENGINE_DBG(x, ...)      fprintf(stderr, "%d:%s:%d " x "\n", getpid(),__FILE__, __LINE__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_DBGFN(x, ...)    fprintf(stderr, "%d:%s:%d %s: " x "\n", getpid(),__FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_ERRFN(x, ...)    fprintf(stderr, "%d:Error in %s:%d %s: " x "\n",getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_MSGFN(x, ...)    fprintf(stderr, "%d:Message:%s:%d %s: " x "\n",getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else

#define TRUSTM_ENGINE_DBG(x, ...)
#define TRUSTM_ENGINE_DBGFN(x, ...)
#define TRUSTM_ENGINE_ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_MSGFN(x, ...)    fprintf(stderr, "Message:%s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif

/*#define TRUSTM_ENGINE_APP_OPEN         if (trustm_ctx.appOpen == 0) \
                                          {trustm_hibernate_flag = 0; \
                                           return_status = trustmEngine_App_Open(); \
                                          }else{trustm_ctx.appOpen = 2;}
*/
/*#define TRUSTM_ENGINE_APP_OPEN_RET(x,y)  if (trustm_ctx.appOpen == 0) \
                                           {trustm_hibernate_flag = 0; \
                                            return_status = trustmEngine_App_Open(); \
                                            if (return_status != OPTIGA_LIB_SUCCESS) { \
                                               TRUSTM_ENGINE_ERRFN("Fail to open trustM!!"); \
                                               x = y;return x;} \
                                           }else{trustm_ctx.appOpen = 2;}
*/                                           
//#define TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE   trustmProvider_SSLMutex_Acquire();
//#define TRUSTM_PROVIDER_SSL_MUTEX_RELEASE   trustmProvider_SSLMutex_Release();

#define TRUSTM_PROVIDER_SSL_MUTEX_ACQUIRE   trustmProvider_App_Open_Recovery();
#define TRUSTM_PROVIDER_SSL_MUTEX_RELEASE   trustmProvider_App_Release();

#ifdef TRUST_ENG_CLOSE_APP_ENABLE
#define TRUSTM_ENGINE_APP_CLOSE           trustmProvider_App_Close(); 
#else
#define TRUSTM_ENGINE_APP_CLOSE           trustmProvider_App_Release(); 
#endif                                          

//Macro define
/// Definition for false
#ifndef FALSE
#define FALSE               (0U)
#endif

/// Definition for true
#ifndef TRUE
#define TRUE                (1U)
#endif

// trustm engine return code
#define TRUSTM_ENGINE_SUCCESS	1
#define TRUSTM_ENGINE_FAIL		0

/*
Shared SSL mutex across functions
*/
//extern shared_mutex_t ssl_mutex;


/*
 * OpenSSL functions typically return 1 on success 
 * EVP probably means "enveloped" (Stack Overflow).
 */
#define EVP_SUCCESS ( 1)
#define EVP_FAIL    (-1)

#define PUBKEYFILE_SIZE 256
#define PUBKEY_SIZE 1024


//typedefine
typedef enum trustmEngine_flag
{
    TRUSTM_ENGINE_FLAG_NONE = 0x00,
    TRUSTM_ENGINE_FLAG_NEW = 0x01,
    TRUSTM_ENGINE_FLAG_SAVEPUBKEY = 0x02,
    TRUSTM_ENGINE_FLAG_LOADPUBKEY = 0x02,
    TRUSTM_ENGINE_FLAG_LOCK = 0x80
} trustmEngine_flag_t;

typedef struct trustm_ctx_str
{
  //char      key[KEY_CONTEXT_MAX_LEN];
  optiga_crypt_t * me_crypt;
  optiga_util_t * me_util;

// for openssl stuff
  const OSSL_CORE_HANDLE *core;
  OSSL_LIB_CTX *libctx;  
} trustm_ctx_t;

//extern
extern trustm_ctx_t *trustm_ctx;

// digest data struct
#define DIGEST_SIZE     32 // in bytes


typedef struct trustm_digest_data_str {
    optiga_hash_context_t hash_context;
    hash_data_from_host_t hash_data_host;
    uint8_t digest[DIGEST_SIZE];
    uint8_t hash_context_buffer[OPTIGA_HASH_CONTEXT_LENGTH_SHA_256];
} trustm_digest_data_t;

// rsa key struct to use across functions
typedef struct trustm_rsa_key_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    // private key oids
    optiga_key_id_t private_key_id;

    // optiga trustm's side variables
    optiga_rsa_key_type_t key_size;
    optiga_key_usage_t key_usage;

    uint8_t public_key[1024];
    uint16_t public_key_length;
    uint16_t public_key_header_length;

    uint8_t modulus[300];
    uint16_t modulus_length;
    uint32_t exponent;
} trustm_rsa_key_t;


// ec key struct to use across functions
typedef struct trustm_ec_key_str {
    const OSSL_CORE_HANDLE *core;
    optiga_crypt_t *me_crypt;
    optiga_util_t *me_util;

    // private key oids
    optiga_key_id_t private_key_id;

    optiga_ecc_curve_t key_curve;
    optiga_key_usage_t key_usage;

    uint8_t public_key[500];
    uint16_t public_key_length;
    uint16_t public_key_header_length;

    uint8_t x[400];
    uint8_t y[400];
    uint16_t point_x_buffer_length;
    uint16_t point_y_buffer_length;
} trustm_ec_key_t;

//function prototype
int mssleep(long msec);

optiga_lib_status_t trustmProvider_Open(void);
optiga_lib_status_t trustmProvider_App_Open(void);
optiga_lib_status_t trustmProvider_App_Open_Recovery(void);

optiga_lib_status_t trustmProvider_Close(void);
optiga_lib_status_t trustmProvider_App_Close(void);
void trustmProvider_App_Release(void);

void trustmProvider_SSLMutex_Acquire(void);
void trustmProvider_SSLMutex_Release(void);



// OSSL core functions
int init_core_func_from_dispatch(const OSSL_DISPATCH *fns);
void trustm_new_error(const OSSL_CORE_HANDLE *handle, uint32_t reason, const char *fmt, ...);
void trustm_set_error_debug(const OSSL_CORE_HANDLE *handle, const char *file, int line, const char *func);


#define TRUSTM_ERROR_raise(core, reason) TRUSTM_ERROR_raise_text(core, reason, NULL)
#define TRUSTM_ERROR_raise_text(core, reason, ...) (trustm_new_error((core), (reason), __VA_ARGS__), TRUSTM_ERROR_set_debug(core))
#define TRUSTM_ERROR_set_debug(core) trustm_set_error_debug((core), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC)
//


#define TRUSTM_MAX_OSSL_NAME  50

// OSSL error enum with TRUSTM
enum {
  TRUSTM_ERR_INIT_FAILURE = 1,
  TRUSTM_ERR_CANNOT_GET_RANDOM
};

// OSSL params for RSA key genereation
#define TRUSTM_PRIVATE_RSA_KEY_OID              "rsa-key"
//

// OSSL params for EC key generation
#define TRUSTM_PRIVATE_EC_KEY_OID               "ec-key"

// OSSL params for general key generation
#define TRUSTM_KEY_USAGE                        "usage"
#define TRUSTM_PUBLIC_KEY_SAVE                  "save-pubkey"
//


optiga_lib_status_t trustmProvider_WaitForCompletion(uint16_t wait_time);


#endif // _TRUSTM_ENGINE_COMMON_H_
