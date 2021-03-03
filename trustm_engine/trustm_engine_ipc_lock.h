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
#ifndef _TRUSTM_ENGINE_IPC_LOCK_H_
#define _TRUSTM_ENGINE_IPC_LOCK_H_

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
//#define TRUSTM_ENGINE_IPC_LOCK_DEBUG

#ifdef TRUSTM_ENGINE_IPC_LOCK_DEBUG
#define TRUSTM_ENGINE_IPCDBG(x, ...)      fprintf(stderr, x"\n", ##__VA_ARGS__)
#else
#define TRUSTM_ENGINE_IPCDBG(x, ...)
#endif

// Function Prototype

void __trustmEngine_ipcInit(void);
void trustmEngine_ipc_acquire(void);
void trustmEngine_ipc_release(void);


#endif  // _TRUSTM_ENGINE_IPC_LOCK_H_
