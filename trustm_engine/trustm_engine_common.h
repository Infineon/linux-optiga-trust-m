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
#ifndef _TRUSTM_ENGINE_COMMON_H_
#define _TRUSTM_ENGINE_COMMON_H_

#include <stdio.h>

// SETTINGS
#define OBJ_MAX_LEN          (128) /* Maximum length for key object paths or passwords */
#define KEY_CONTEXT_MAX_LEN  (100)
#define PARAM_MAX_LEN        (128)

//#define TRUSTM_ENGINE_DEBUG = 1

#ifdef TRUSTM_ENGINE_DEBUG

#define TRUSTM_ENGINE_DBG(x, ...)      fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_DBGFN(x, ...)    fprintf(stderr, "%s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define TRUSTM_ENGINE_ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#else

#define TRUSTM_ENGINE_DBG(x, ...)
#define TRUSTM_ENGINE_DBGFN(x, ...)
#define TRUSTM_ENGINE_ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

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
 * OpenSSL functions typically return 1 on success 
 * EVP probably means "enveloped" (Stack Overflow).
 */
#define EVP_SUCCESS ( 1)
#define EVP_FAIL    (-1)


#endif // _TRUSTM_ENGINE_COMMON_H_
