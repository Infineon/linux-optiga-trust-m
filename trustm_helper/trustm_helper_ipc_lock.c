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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

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

#include "trustm_helper.h"
#include "trustm_helper_ipc_lock.h"


/*************************************************************************
*  Global
*************************************************************************/

/*************************************************************************
*  functions
*************************************************************************/


/**********************************************************************
* trustm_ipc_acquire()
**********************************************************************/

void trustm_ipc_acquire(shared_mutex_t* shm_mutex, const  char* mutex_name)
{
    
    int result;
    TRUSTM_HELPER_DBGFN(">");
    
    *shm_mutex= shared_mutex_init(mutex_name);
    if (shm_mutex->ptr == NULL) {
        TRUSTM_HELPER_DBGFN("Mutex create failed\n");
          return;
       }

       
      
    result = pthread_mutex_lock(shm_mutex->ptr);
    TRUSTM_HELPER_DBGFN("Lock Mutex:%s: %x\n",mutex_name,(unsigned int)shm_mutex->ptr);
	if (result == EOWNERDEAD)
	{
		result = pthread_mutex_consistent(shm_mutex->ptr);
		if (result != 0)
			perror("pthread_mutex_consistent");
        TRUSTM_HELPER_DBGFN("process owner dead, make it consistent\n");     
	}
    if (shm_mutex->created) {
            TRUSTM_HELPER_DBGFN("The mutex was just created %x\n",*shm_mutex->pid);
            *shm_mutex->pid = EMPTY_PID;
       }
    
    TRUSTM_MUTEX_DBGFN("<");
}

/**********************************************************************
* trustm_ipc_release(void)
**********************************************************************/
void trustm_ipc_release(shared_mutex_t* shm_mutex)
{
  TRUSTM_HELPER_DBGFN(">");
  pthread_mutex_unlock(shm_mutex->ptr); 
  TRUSTM_HELPER_DBGFN("mutex unlock:%s:%x",shm_mutex->name, (unsigned int)shm_mutex->ptr);
 
  shared_mutex_close(*shm_mutex);
  TRUSTM_HELPER_DBGFN("mutex closed");
  
   TRUSTM_HELPER_DBGFN("<");
  
}



