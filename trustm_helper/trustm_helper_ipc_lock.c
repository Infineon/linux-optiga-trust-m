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
//Globe Variable
// for IPC
// ---- InterCom
#define IPC_FLAGSIZE    sizeof(pid_t)
#define IPC_SLEEP_STEPS 1
#define MAX_IPC_TIME 50

key_t ipc_FlagInterKey;
int   ipc_FlagInterShmid;
pid_t ipc_queue;
unsigned char ipc_value;
unsigned char ipc_temp;
long ipc_task;
/*************************************************************************
*  functions
*************************************************************************/

/**********************************************************************
* __trustm_writeshm()
**********************************************************************/
static void __trustm_writeshm(int shmid,pid_t data)
{
    pid_t  *Flag_segptr;

    /* Attach (map) the shared memory segment into the current process */
     if((Flag_segptr = (pid_t *)shmat(shmid, 0, 0)) == (pid_t *)-1)
     {
             perror("write flag shmat");
             //exit(1);
             return;
     }

     *Flag_segptr=data;
     shmdt(Flag_segptr);
}

/**********************************************************************
* __trustm_readshm()
**********************************************************************/
static pid_t __trustm_readshm(int shmid)
{   pid_t  *Flag_segptr;
    pid_t Flag;
    /* Attach (map) the shared memory segment into the current process */
     if((Flag_segptr = (pid_t *)shmat(shmid, 0, 0)) == (pid_t *)-1)
     {
             perror("read flag shmat");
             //exit(1);
             return 0;
     }
     Flag = *Flag_segptr;
     shmdt(Flag_segptr);

    return Flag;
}

/**********************************************************************
* __trustm_ipcInit()
**********************************************************************/
void __trustm_ipcInit(void)
{
	/* Unique Key for InterCom */
    ipc_FlagInterKey = 0x11111123;
    pid_t pid;

  	/* Open the shared memory segment - create if necessary */
    if((ipc_FlagInterShmid = shmget(ipc_FlagInterKey, IPC_FLAGSIZE, IPC_CREAT|IPC_EXCL|0666)) == -1)
    {
        TRUSTM_HELPER_DBGFN("Shared memory segment exists - opening as client");
        /* Segment probably already exists - try as a client */
        if((ipc_FlagInterShmid = shmget(ipc_FlagInterKey, IPC_FLAGSIZE, 0)) == -1)
        {
            perror("Init shmget");
            exit(1);
        }
    }
    else
    {
        // First created so init queue
        pid=getpid();
        TRUSTM_HELPER_DBGFN("Init Queue %d", pid);
        
        //~ __trustm_writeshm(ipc_FlagInterShmid,0x1);
        __trustm_writeshm(ipc_FlagInterShmid,pid); // stores the current PID
    }
}

/**********************************************************************
* trustm_ipc_acquire()
**********************************************************************/
void trustm_ipc_acquire(void)
{
    pid_t current_pid;
    pid_t queue_pid;
    int queue_delay;

     __trustm_ipcInit();

    /// IPC Check
    current_pid=getpid();
    queue_delay= ((current_pid %MAX_IPC_TIME)+1)*IPC_SLEEP_STEPS;; // wait for 0 to 20ms at IPC_SLEEP_STEPS steps depends on process number
    mssleep(queue_delay);
    
    queue_pid = __trustm_readshm(ipc_FlagInterShmid);
    TRUSTM_HELPER_DBGFN("Check if TrustM Open:queue %d:current:%d:Delay %d", queue_pid,current_pid,queue_delay);
    if (queue_pid ==0xAA55)
    {    __trustm_writeshm(ipc_FlagInterShmid,current_pid); /*write pid into shared memory*/
        queue_pid = __trustm_readshm(ipc_FlagInterShmid);
        TRUSTM_HELPER_DBGFN("Resource seized by %d",current_pid);
    }    
   
    while ( queue_pid !=current_pid)  /*Check if taken by other process and wait*/
    {
        queue_pid = __trustm_readshm(ipc_FlagInterShmid);
        if (queue_pid ==0XAA55)
        {    __trustm_writeshm(ipc_FlagInterShmid,current_pid); /*write pid into shared memory*/
            //queue_pid=__trustm_readshm(ipc_FlagInterShmid);
            TRUSTM_HELPER_DBGFN("Resource seized by %d",current_pid);
        }
        else if (kill(queue_pid,0) == -1) 
        {
          mssleep(100); 
          queue_pid = __trustm_readshm(ipc_FlagInterShmid);
          if (kill(queue_pid,0) == -1)
          {
              TRUSTM_HELPER_DBGFN("Process does not exist1:%d", queue_pid);
              __trustm_writeshm(ipc_FlagInterShmid,current_pid);
              //queue_pid=__trustm_readshm(ipc_FlagInterShmid);
            }
        }
        queue_delay= ((current_pid %MAX_IPC_TIME)+1)*IPC_SLEEP_STEPS; // wait for 1 to MAX_IPC_TIME at IPC_SLEEP_STEPS steps depends on process number
        mssleep(queue_delay);
        queue_pid=__trustm_readshm(ipc_FlagInterShmid);
    }
    TRUSTM_HELPER_DBGFN("Lock queue %d", queue_pid);
    
}

/**********************************************************************
* trustm_ipc_release(void)
**********************************************************************/
void trustm_ipc_release(void)
{
    pid_t current_pid;
    pid_t queue_pid;  
    current_pid=getpid();
    queue_pid = __trustm_readshm(ipc_FlagInterShmid);
    if (current_pid==queue_pid)
    {
        TRUSTM_HELPER_DBGFN("release shared memory\n");
        __trustm_writeshm(ipc_FlagInterShmid,0xAA55);
    }
    else if (queue_pid!=0xAA55)
    {   TRUSTM_HELPER_DBGFN("shared memory used by others\n");
    }
    mssleep(30);
}
