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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <openssl/engine.h>

#include "optiga_lib_common.h"

#include "trustm_engine_common.h"
#include "trustm_engine_ipc_lock.h"


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
* __trustmEngine_writeshm()
**********************************************************************/
static void __trustmEngine_writeshm(int shmid,pid_t data)
{
    pid_t  *Flag_segptr;

    /* Attach (map) the shared memory segment into the current process */
     if((Flag_segptr = (pid_t *)shmat(shmid, 0, 0)) == (pid_t *)-1)
     {
             perror("write flag shmat");
             return;
             //exit(1);
     }

     *Flag_segptr=data;
     shmdt(Flag_segptr);
}

/**********************************************************************
* __trustmEngine_readshm()
**********************************************************************/
static pid_t __trustmEngine_readshm(int shmid)
{   pid_t  *Flag_segptr;
    pid_t Flag;
    /* Attach (map) the shared memory segment into the current process */
     if((Flag_segptr = (pid_t *)shmat(shmid, 0, 0)) == (pid_t *)-1)
     {
             perror("read flag shmat");
             return 0;
             //exit(1);
     }
     Flag = *Flag_segptr;
     shmdt(Flag_segptr);

    return Flag;
}

/**********************************************************************
* __trustmEngine_ipcInit()
**********************************************************************/
void __trustmEngine_ipcInit(void)
{
	/* Unique Key for InterCom */
    ipc_FlagInterKey = 0x11111123;
    pid_t pid;

  	/* Open the shared memory segment - create if necessary */
    if((ipc_FlagInterShmid = shmget(ipc_FlagInterKey, IPC_FLAGSIZE, IPC_CREAT|IPC_EXCL|0666)) == -1)
    {
        TRUSTM_ENGINE_DBGFN("Shared memory segment exists - opening as client");
        /* Segment probably already exists - try as a client */
        if((ipc_FlagInterShmid = shmget(ipc_FlagInterKey, IPC_FLAGSIZE, 0)) == -1)
        {
            TRUSTM_ENGINE_DBGFN("share mem error %d",ipc_FlagInterShmid);
            perror("Init shmget");
            //shmctl(shmid, IPC_RMID, 0);
            
            exit(1);
        }
    }
    else
    {
        // First created so init queue
        pid=getpid();
        TRUSTM_ENGINE_DBGFN("Init Queue %d", pid);
        
        //~ __trustmEngine_writeshm(ipc_FlagInterShmid,0x1);
        __trustmEngine_writeshm(ipc_FlagInterShmid,pid); // stores the current PID

        
    }
}

/**********************************************************************
* trustmEngine_ipc_acquire()
**********************************************************************/
void trustmEngine_ipc_acquire(void)
{
    pid_t current_pid;
    pid_t queue_pid;
    int queue_delay;

    __trustmEngine_ipcInit();
    /// IPC Check
    current_pid=getpid();
    queue_delay= ((current_pid %MAX_IPC_TIME)+1)*IPC_SLEEP_STEPS;; // wait for 0 to 20ms at IPC_SLEEP_STEPS steps depends on process number
    mssleep(queue_delay);
    
    queue_pid = __trustmEngine_readshm(ipc_FlagInterShmid);
    TRUSTM_ENGINE_DBGFN("Check if TrustM Open:queue %d:current:%d:Delay %d", queue_pid,current_pid,queue_delay);
    if (queue_pid ==0xAA55)
    {    __trustmEngine_writeshm(ipc_FlagInterShmid,current_pid); /*write pid into shared memory*/
        queue_pid = __trustmEngine_readshm(ipc_FlagInterShmid);
        TRUSTM_ENGINE_DBGFN("Resource seized by %d",current_pid);
    }    
   
    while ( queue_pid !=current_pid)  /*Check if taken by other process and wait*/
    {
        queue_pid = __trustmEngine_readshm(ipc_FlagInterShmid);
        if (queue_pid ==0xAA55)
        {    __trustmEngine_writeshm(ipc_FlagInterShmid,current_pid); /*write pid into shared memory*/
            //queue_pid=__trustmEngine_readshm(ipc_FlagInterShmid);
            TRUSTM_ENGINE_DBGFN("Resource seized by %d",current_pid);
        }
        else if (kill(queue_pid,0) == -1) 
        {
          mssleep(50);
          queue_pid = __trustmEngine_readshm(ipc_FlagInterShmid); 
          if (kill(queue_pid,0) == -1)
          {          
            TRUSTM_ENGINE_DBGFN("Process does not exist1:%d", queue_pid);
            __trustmEngine_writeshm(ipc_FlagInterShmid,current_pid);
            //queue_pid=__trustmEngine_readshm(ipc_FlagInterShmid);
            }
        }
        queue_delay= ((current_pid %MAX_IPC_TIME)+1)*IPC_SLEEP_STEPS; // wait for 1 to MAX_IPC_TIME at IPC_SLEEP_STEPS steps depends on process number
        mssleep(queue_delay);
        queue_pid=__trustmEngine_readshm(ipc_FlagInterShmid);
    }
 
    TRUSTM_ENGINE_DBGFN("Lock queue %d", queue_pid);

}

/**********************************************************************
* trustmEngine_ipc_release(void)
**********************************************************************/
void trustmEngine_ipc_release(void)
{
    pid_t current_pid;
    pid_t queue_pid;  
    current_pid=getpid();
    queue_pid = __trustmEngine_readshm(ipc_FlagInterShmid);
    if (current_pid==queue_pid)
    {
        TRUSTM_ENGINE_DBGFN("release shared memory\n");
        __trustmEngine_writeshm(ipc_FlagInterShmid,0xAA55);
    }
    else if (queue_pid!=0xAA55)
    {   TRUSTM_ENGINE_DBGFN("shared memory used by others\n");
    }
     mssleep(30);
}
