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
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <openssl/engine.h>

#include "optiga/pal/pal_ifx_i2c_config.h"
#include "trustm_helper.h"
#include "trustm_helper_ipc_lock.h"

#include "trustm_engine_common.h"



#ifdef WORKAROUND
	extern void pal_os_event_disarm(void);
	extern void pal_os_event_arm(void);
	extern void pal_os_event_destroy1(void);
#endif

trustm_ctx_t trustm_ctx;
shared_mutex_t trustm_eng_mutex;
shared_mutex_t ssl_mutex;

extern void pal_os_event_disarm(void);

static const char *engine_id   = "trustm_engine";
static const char *engine_name = "Infineon OPTIGA TrustM Engine";

/**********************************************************************
* mssleep()
**********************************************************************/
int mssleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}
/**********************************************************************
* engine_optiga_util_callback()
**********************************************************************/
void engine_optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    TRUSTM_HELPER_DBGFN("optiga_lib_status: %x\n",optiga_lib_status);
}

/**********************************************************************
* engine_optiga_crypt_callback()
**********************************************************************/
void engine_optiga_crypt_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}

/**********************************************************************
* __trustmEngine_delay()
**********************************************************************/
/*
static void __trustmEngine_delay (int cnt)
{
    uint32_t wait;

    for(wait=0;wait<(0x1fffffff*cnt);wait++)
    {}
}
*/
/**********************************************************************
* trustmEngine_WaitForCompletion()
**********************************************************************/
optiga_lib_status_t trustmEngine_WaitForCompletion(uint16_t wait_time)
{
    uint16_t tickcount;
     
    tickcount=0;
    do
    {
        mssleep(1);
        tickcount++;
        if (tickcount >= wait_time)
        {
            TRUSTM_ENGINE_ERRFN("Fail : Optiga Busy Time Out:%d\n",tickcount);
            return OPTIGA_LIB_BUSY;
        }
         
    }while (optiga_lib_status == OPTIGA_LIB_BUSY);
    TRUSTM_ENGINE_DBGFN(" max wait_time:%d, Tick Counter: %d", wait_time,tickcount);
    return optiga_lib_status;
    
}

/**********************************************************************
* __trustmEngine_secCnt()
**********************************************************************/
/*
static uint8_t __trustmEngine_secCnt(void)
{
    uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[5];

    optiga_lib_status_t return_status;

    // Do not add open_close here.
    do
    {
        //Read device Security Event ounter
        optiga_oid = 0xE0C5;
        offset = 0x00;
        bytes_to_read = sizeof(read_data_buffer);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_read_data(me_util,
                                              optiga_oid,
                                              offset,
                                              read_data_buffer,
                                              &bytes_to_read);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            //Reading the data object failed.
            TRUSTM_ENGINE_ERRFN("optiga_util_read_data : FAIL!!!\n");
            read_data_buffer[0] = 0;
            break;
        }

        trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            read_data_buffer[0] = 0;
            break;
        }        

    } while(FALSE);

    return read_data_buffer[0];
}
*/
/**********************************************************************
* trustmEngine_Open()
**********************************************************************/
optiga_lib_status_t trustmEngine_Open(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_ENGINE_DBGFN(">");

    do
    {
        
        //Create an instance of optiga_util to open the application on OPTIGA.
        trustm_ipc_acquire(&trustm_eng_mutex,"/trustm-mutex");
        if (me_util == NULL)
        {
            me_util = optiga_util_create(0, engine_optiga_util_callback, NULL);
            if (NULL == me_util)
            {
                TRUSTM_ENGINE_ERRFN("Fail : optiga_util_create\n");
                return_status = OPTIGA_UTIL_ERROR;
                break;
            }
            TRUSTM_ENGINE_DBGFN("optiga_util_create OK \n");
        }else
        {   TRUSTM_ENGINE_DBGFN("TrustM util instance exists. \n");
        }

        if(me_crypt ==NULL)
        {
            me_crypt = optiga_crypt_create(0, engine_optiga_crypt_callback, NULL);
            if (NULL == me_crypt)
            {
                TRUSTM_ENGINE_ERRFN("Fail : optiga_crypt_create\n");
                return_status = OPTIGA_CRYPT_ERROR;
                break;
            }
            TRUSTM_ENGINE_DBGFN("optiga_crypt_create OK \n");
        }else
        {
            TRUSTM_ENGINE_DBGFN("TrustM crypt instance exists. \n");
        }
        TRUSTM_WORKAROUND_TIMER_ARM;
        return_status = OPTIGA_LIB_SUCCESS;
        TRUSTM_ENGINE_DBGFN("TrustM crypt instance created. \n");
        

    }while(FALSE);      

    TRUSTM_ENGINE_DBGFN("<");
    return return_status;
}


/**********************************************************************
* trustmEngine_App_Open_Recovery()
**********************************************************************/
optiga_lib_status_t trustmEngine_App_Open_Recovery(void)
{
    optiga_lib_status_t return_status;
    
    TRUSTM_ENGINE_DBGFN(">");
      
    trustm_hibernate_flag = 0; 
    return_status = trustmEngine_App_Open();
    if (return_status != OPTIGA_LIB_SUCCESS) 
    { 
       TRUSTM_ENGINE_DBGFN("Error opening Trust M, Retry 1");
      
       trustmEngine_App_Close();
       return_status = trustmEngine_App_Open();
       if (return_status != OPTIGA_LIB_SUCCESS)
       {
           TRUSTM_ENGINE_ERRFN("Error opening Trust M, EXIT");
        }            
    }    
     
    TRUSTM_ENGINE_DBGFN("<");
    return return_status;
}

/**********************************************************************
* trustmEngine_App_Open()
**********************************************************************/
optiga_lib_status_t trustmEngine_App_Open(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_ENGINE_DBGFN(">");
    do
    {
       
        return_status = trustmEngine_Open();
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            TRUSTM_ENGINE_ERRFN("Fail to create instances");
            break;
        }
        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */        
        if(*trustm_eng_mutex.pid==EMPTY_PID || *trustm_eng_mutex.pid != getpid() )
        {   
            TRUSTM_ENGINE_DBGFN("optiga_util_open_application:Init");
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_open_application(me_util, 0);
            
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                TRUSTM_ENGINE_ERRFN("Fail : optiga_util_open_application[1] \n");
                break;
            }
            //Wait until the optiga_util_open_application is completed
            return_status=trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            if (return_status != OPTIGA_LIB_SUCCESS)
            {   TRUSTM_ENGINE_ERRFN("Fail : optiga_util_open_application time out[1] \n");
                trustmPrintErrorCode(return_status);
                break;
            }
            *trustm_eng_mutex.pid = getpid(); 
        }
        
        
        TRUSTM_ENGINE_DBGFN("Success : optiga_util_open_application \n");
    }while(FALSE);      

    TRUSTM_ENGINE_DBGFN("<");
    return return_status;
}



/**********************************************************************
* trustmEngine_Close()
**********************************************************************/
optiga_lib_status_t trustmEngine_Close(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_ENGINE_DBGFN(">");

    // destroy util and crypt instances
    if (me_crypt!=NULL)
    {
        TRUSTM_ENGINE_DBGFN("optiga_crypt_destroy\n");
        return_status = optiga_crypt_destroy(me_crypt);
        if(OPTIGA_LIB_SUCCESS != return_status)
        {
        TRUSTM_ENGINE_ERRFN("Fail : optiga_crypt_destroy \n");
        }
    }

    if (me_util != NULL)
    {   TRUSTM_ENGINE_DBGFN("optiga_util_destroy\n");
        return_status=optiga_util_destroy(me_util);   
    }
    TRUSTM_WORKAROUND_TIMER_DISARM;

    // No point deinit the GPIO as it is a fix pin
    //pal_gpio_deinit(&optiga_reset_0);
    //pal_gpio_deinit(&optiga_vdd_0);
    me_util=NULL;
    me_crypt=NULL;    
    TRUSTM_ENGINE_DBGFN("TrustM instance destroyed.\n");
    TRUSTM_ENGINE_DBGFN("<");
    return return_status;
}

/**********************************************************************
* trustmEngine_App_Close()
**********************************************************************/
optiga_lib_status_t trustmEngine_App_Close(void)
{
    optiga_lib_status_t return_status;
    

    TRUSTM_HELPER_DBGFN(">");

    do{

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(me_util, 0);
            
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_close_application \n");
            break;
        }

        return_status=trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_ENGINE_ERRFN("Fail : optiga_util_close_application time out \n");
            break;
        }
        TRUSTM_ENGINE_DBGFN("Success : optiga_util_close_application \n");

    }while(FALSE);

    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);
    trustmEngine_Close();
    
    *trustm_eng_mutex.pid=EMPTY_PID;
    trustm_ipc_release(&trustm_eng_mutex);
    TRUSTM_ENGINE_DBGFN("<");
    return return_status;
}


/**********************************************************************
* trustmEngine_App_Release()
**********************************************************************/
void trustmEngine_App_Release(void)
{
    TRUSTM_ENGINE_DBGFN(">");
    TRUSTM_WORKAROUND_TIMER_DISARM;
    trustm_ipc_release(&trustm_eng_mutex);
    TRUSTM_ENGINE_DBGFN("<");
      
    }


static uint32_t parseKeyParams(const char *aArg)
{   
    uint32_t ret;
    uint32_t value;
    char in[1024];

    char *token[5];
    int   i, j;
    
    trustm_metadata_t oidMetadata;

    FILE *fp;
    char *name;
    char *header;
    uint8_t *data;
    uint32_t len;
    
    optiga_lib_status_t return_status;
    uint16_t offset =0;
    uint32_t bytes_to_read;
    uint8_t read_data_buffer[2048];
    const char needle[3] = "0x";    
    char *ptr;
    TRUSTM_ENGINE_DBGFN(">");
    
    TRUSTM_ENGINE_APP_OPEN_RET(NULL,NULL);
    //~ TRUSTM_WORKAROUND_TIMER_ARM;
    do
    {
        strcpy(in, aArg);
        ptr=strstr(in,needle);
        strcpy((char *)aArg,ptr);
                
        if (aArg == NULL)
        {
            TRUSTM_ENGINE_ERRFN("No input key parameters present. (key_oid:<pubkeyfile>)");
            //return EVP_FAIL;
            ret = 0;
            break;
        }
          
        i = 0;
        token[0] = strtok((char *)aArg, ":");
        
        if (token[0] == NULL)
        {
            TRUSTM_ENGINE_ERRFN("Too few parameters in key parameters list. (key_oid:<pubkeyfile>)");
            //return EVP_FAIL;
            ret = 0;
            break;
        }

        while (token[i] != NULL)
        {
            i++;
            token[i] = strtok(NULL, ":");
        }

        if (i > 6)
        {
            TRUSTM_ENGINE_ERRFN("Too many parameters in key parameters list. (key_oid:<pubkeyfile>)");
            //return EVP_FAIL;
            ret = 0;
            break;
        }
        
        TRUSTM_ENGINE_DBGFN("---> token [0] = %s",token[0]);
        
        if (strncmp(token[0], "0x",2) == 0)
            sscanf(token[0],"%x",&value);
        else
            value = 0;

        if (((value < 0xE0F0) || (value > 0xE0F3)) &&
            ((value < 0xE0FC) || (value > 0xE0FD)))
        {
            TRUSTM_ENGINE_ERRFN("Invalid Key OID");
            //return EVP_FAIL;
            ret = 0;
            break;
        }
        else
        {          
            trustm_ctx.key_oid = value;
            
            trustmReadMetadata(value, &oidMetadata);          
            
            if ((oidMetadata.E0_algo == OPTIGA_ECC_CURVE_NIST_P_256) ||
                (oidMetadata.E0_algo == OPTIGA_ECC_CURVE_NIST_P_384) ||
                (oidMetadata.E0_algo == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1) ||
                (oidMetadata.E0_algo == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1))
            {
                trustm_ctx.ec_key_curve = oidMetadata.E0_algo;
                trustm_ctx.ec_key_usage = oidMetadata.E1_keyUsage;
                trustm_ctx.rsa_key_type = 0x00;
                trustm_ctx.rsa_key_usage = 0x00;
                trustm_ctx.pubkeyStore = trustm_ctx.key_oid + 0x10E0;
            }
            if ((oidMetadata.E0_algo == OPTIGA_ECC_CURVE_NIST_P_521) ||
                (oidMetadata.E0_algo == OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1))
            {
                trustm_ctx.ec_key_curve = oidMetadata.E0_algo;
                trustm_ctx.ec_key_usage = oidMetadata.E1_keyUsage;
                trustm_ctx.rsa_key_type = 0x00;
                trustm_ctx.rsa_key_usage = 0x00;
                trustm_ctx.pubkeyStore = trustm_ctx.key_oid + 0x10ED;
            }
            
            if ((oidMetadata.E0_algo == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL) ||
                (oidMetadata.E0_algo == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL))
            {
                trustm_ctx.rsa_key_type = oidMetadata.E0_algo;
                trustm_ctx.rsa_key_usage = oidMetadata.E1_keyUsage;
                trustm_ctx.ec_key_curve = 0x00;
                trustm_ctx.ec_key_usage = 0x00;
                trustm_ctx.pubkeyStore = trustm_ctx.key_oid + 0x10E4;
            } 
        }
       
        // If token is not empty or '*' then it must be a pubkeyfile.
        if ((token[1] != NULL) && (*(token[1]) != '*') && (*(token[1]) != '^'))
        {
            strncpy(trustm_ctx.pubkeyfilename, token[1], PUBKEYFILE_SIZE);
            
            fp = fopen((const char *)trustm_ctx.pubkeyfilename,"r");
            if (!fp)
            {
                TRUSTM_ENGINE_ERRFN("failed to open file %s\n",trustm_ctx.pubkeyfilename);
                break;
            }
            PEM_read(fp, &name,&header,&data,(long int *)&len);
            if (!(strcmp(name,"PUBLIC KEY")))
            {
                trustm_ctx.pubkeylen = (uint16_t)len;
                j=0;
                for(i=0;i<len;i++)
                {
                    trustm_ctx.pubkey[i] = *(data+i);
                }
                
                if((trustm_ctx.pubkey[1] & 0x80) == 0x00)
                    j = trustm_ctx.pubkey[3] + 4;
                else
                {
                    j = (trustm_ctx.pubkey[1] & 0x7f);
                    j = trustm_ctx.pubkey[j+3] + j + 4; 
                }
                trustm_ctx.pubkeyHeaderLen = j;
            }
        }
        else
        {
            trustm_ctx.pubkeyfilename[0]='\0';
            trustm_ctx.pubkeyHeaderLen = 0;
            trustm_ctx.pubkeylen = 0;

            if((i > 1) && (*(token[1]) == '^'))
            {
                trustm_ctx.ec_flag |= TRUSTM_ENGINE_FLAG_SAVEPUBKEY;
                trustm_ctx.rsa_flag |= TRUSTM_ENGINE_FLAG_SAVEPUBKEY;                
            }

            if(i == 2)
            {
                bytes_to_read = sizeof(read_data_buffer);
                optiga_lib_status = OPTIGA_LIB_BUSY;
                return_status = optiga_util_read_data(me_util,
                                                    trustm_ctx.pubkeyStore,
                                                    offset,
                                                    read_data_buffer,
                                                    (uint16_t *)&bytes_to_read);
                if (OPTIGA_LIB_SUCCESS != return_status)
                    break;			
                //Wait until the optiga_util_read_metadata operation is completed
                trustmEngine_WaitForCompletion(BUSY_WAIT_TIME_OUT);
                return_status = optiga_lib_status;
                if (return_status != OPTIGA_LIB_SUCCESS)
                    break;
                else
                {
                    TRUSTM_ENGINE_DBGFN("Load Pubkey from : 0x%.4X",trustm_ctx.pubkeyStore);

                    for(i=0;i<bytes_to_read;i++)
                    {
                        trustm_ctx.pubkey[i] = *(read_data_buffer+i);
                    }                        

                    trustm_ctx.pubkeylen = (uint16_t) bytes_to_read;                    
                    j=0;
                    if((trustm_ctx.pubkey[1] & 0x80) == 0x00)
                        j = trustm_ctx.pubkey[3] + 4;
                    else
                    {
                        j = (trustm_ctx.pubkey[1] & 0x7f);
                        j = trustm_ctx.pubkey[j+3] + j + 4; 
                    }
                    trustm_ctx.pubkeyHeaderLen = j;
                } 
            }
        }

        if ((i>2) && (token[2] != NULL))
        {
            if (!strcmp(token[2],"NEW"))
            {
                // Request NEW key generation
                if (((value >= 0xE0FC) && (value <= 0xE0FD)))
                {
                    TRUSTM_ENGINE_DBGFN("found NEW\n");
                    trustm_ctx.rsa_flag |= TRUSTM_ENGINE_FLAG_NEW;
                    if ((i>3) && (strncmp(token[3], "0x",2) == 0))
                        sscanf(token[3],"%x",&(trustm_ctx.rsa_key_type));
                    if ((i>4) && (strncmp(token[4], "0x",2) == 0))
                        sscanf(token[4],"%x",&(trustm_ctx.rsa_key_usage));
                    // LOCK function not implemented
                    if ((i>5) && (strcmp(token[5], "LOCK") == 0))
                        trustm_ctx.rsa_flag |= TRUSTM_ENGINE_FLAG_LOCK;
                }
                
                if (((value >= 0xE0F1) && (value <= 0xE0F3)))
                {
                    TRUSTM_ENGINE_DBGFN("found NEW\n");
                    trustm_ctx.ec_flag |= TRUSTM_ENGINE_FLAG_NEW;
                    if ((i>3) && (strncmp(token[3], "0x",2) == 0))
                        sscanf(token[3],"%x",&(trustm_ctx.ec_key_curve));
                    if ((i>4) && (strncmp(token[4], "0x",2) == 0))
                        sscanf(token[4],"%x",&(trustm_ctx.ec_key_usage));
                    if ((i>5) && (strcmp(token[5], "LOCK") == 0))
                        trustm_ctx.ec_flag |= TRUSTM_ENGINE_FLAG_LOCK;
                }
            }
            else
            {
                // No NEW key request
            }
        }        
        ret = value;
    }while(FALSE);
    TRUSTM_ENGINE_APP_CLOSE;

    
    
    TRUSTM_ENGINE_DBGFN("<");

    return ret;
}

static int engine_destroy(ENGINE *e)
{
    uint16_t i;
    
    TRUSTM_ENGINE_DBGFN("> Engine 0x%x destroy", (unsigned int) e);
    trustm_ipc_acquire(&ssl_mutex,"/ssl-mutex");
    //Clear TrustM context
    trustm_ctx.key_oid = 0x0000;
    trustm_ctx.rsa_key_type = 0;
    trustm_ctx.rsa_key_usage = 0;
    trustm_ctx.rsa_key_enc_scheme = 0;
    trustm_ctx.rsa_key_sig_scheme = 0;
    trustm_ctx.rsa_flag = 0;
    
    trustm_ctx.ec_key_curve = 0;
    trustm_ctx.ec_key_usage = 0;   
    trustm_ctx.ec_key_method = NULL; 
    trustm_ctx.ec_flag = 0;
    
    trustm_ctx.pubkeylen = 0;
    trustm_ctx.pubkeyHeaderLen = 0;
        
    for(i=0;i<PUBKEYFILE_SIZE;i++)
    {
        trustm_ctx.pubkeyfilename[i] = 0x00;
    }
    for(i=0;i<PUBKEY_SIZE;i++)
    {
        trustm_ctx.pubkey[i] = 0x00;
    }
    trustmEngine_Close();
    
    trustm_ipc_release(&ssl_mutex);
    TRUSTM_ENGINE_DBGFN("<");
    return TRUSTM_ENGINE_SUCCESS;
}

static int engine_finish(ENGINE *e)
{
    TRUSTM_ENGINE_DBGFN("> Engine 0x%x finish (releasing functional reference)", (unsigned int) e);
    TRUSTM_ENGINE_DBGFN("<");
    return TRUSTM_ENGINE_SUCCESS;
}

/**************************************************************** 
 engine_load_privkey()
 This function implements loading trustx key.
 e        : The engine for this callback (unused).
 key_id   : The name of the file with the TPM key data.
 ui The ui: functions for querying the user.
 cb_data  : Callback data.
*****************************************************************/
static EVP_PKEY * engine_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb_data)
{
    EVP_PKEY    *key         = NULL;    
    
    
    TRUSTM_ENGINE_DBGFN("> key_id : %s", key_id);
    trustm_ipc_acquire(&ssl_mutex,"/ssl-mutex");
    do 
    {
        if(parseKeyParams(key_id) == 0)
        {
            TRUSTM_ENGINE_ERRFN("Invalid OID!!!");
            break;
        }
    
        TRUSTM_ENGINE_DBGFN("KEY_OID       : 0x%.4x",trustm_ctx.key_oid);        
        TRUSTM_ENGINE_DBGFN("Pubkey        : %s",trustm_ctx.pubkeyfilename);
        TRUSTM_ENGINE_DBGFN("PubkeyLen     : %d",trustm_ctx.pubkeylen);
        TRUSTM_ENGINE_DBGFN("PubkeyHeader  : %d",trustm_ctx.pubkeyHeaderLen);
        TRUSTM_ENGINE_DBGFN("PubkeyStore   : 0x%.4X",trustm_ctx.pubkeyStore);

        TRUSTM_ENGINE_DBGFN("RSA key type  : 0x%.2x",trustm_ctx.rsa_key_type);
        TRUSTM_ENGINE_DBGFN("RSA key usage : 0x%.2x",trustm_ctx.rsa_key_usage);    
        TRUSTM_ENGINE_DBGFN("RSA key flag  : 0x%.2x",trustm_ctx.rsa_flag);    

        TRUSTM_ENGINE_DBGFN("EC key type   : 0x%.2x",trustm_ctx.ec_key_curve);
        TRUSTM_ENGINE_DBGFN("EC key usage  : 0x%.2x",trustm_ctx.ec_key_usage);    
        TRUSTM_ENGINE_DBGFN("EC key flag   : 0x%.2x",trustm_ctx.ec_flag);        
        switch(trustm_ctx.key_oid)
        {
            case 0xE0F0:
                //TRUSTM_ENGINE_MSGFN("EC Private Key. [0x%.4X]", trustm_ctx.key_oid);
                key = trustm_ec_loadkeyE0E0();
                break;
            case 0xE0F1:
            case 0xE0F2:
            case 0xE0F3:
                //TRUSTM_ENGINE_MSGFN("EC Private Key");
                key = trustm_ec_loadkey();
                break;
            case 0xE0FC:
            case 0xE0FD:
                //TRUSTM_ENGINE_DBGFN("RSA Private Key.");
                key = trustm_rsa_loadkey();
                break;
            case 0xE100:
            case 0xE101:
            case 0xE102:
            case 0xE103:
                TRUSTM_ENGINE_MSGFN("Function Not implemented.");
                break;
            default:
                TRUSTM_ENGINE_ERRFN("Invalid OID!!!");
        }
        
    }while(FALSE);
    TRUSTM_WORKAROUND_TIMER_DISARM;
    trustm_ipc_release(&ssl_mutex);
    TRUSTM_ENGINE_DBGFN("<");
    return key;
}

/**************************************************************** 
 engine_load_pubkey()
 This function implements loading trustx key.
 e        : The engine for this callback (unused).
 key_id   : The name of the file with the TPM key data.
 ui The ui: functions for querying the user.
 cb_data  : Callback data.
*****************************************************************/
static EVP_PKEY * engine_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb_data)
{
    EVP_PKEY    *key         = NULL;    
    FILE *fp;
    char *name;
    char *header;
    uint8_t *data;
    uint32_t len;
    uint16_t i;
        
    TRUSTM_ENGINE_DBGFN("> key_id : %s", key_id);
    trustm_ipc_acquire(&ssl_mutex,"/ssl-mutex");
    do {
        if (key_id == NULL)
        {
            TRUSTM_ENGINE_ERRFN("No input key parameters present. (key_oid:<pubkeyfile>)");
            break;
        }
        
        strcpy(trustm_ctx.pubkeyfilename, key_id);
                
        if (trustm_ctx.pubkeyfilename[0] != '\0')
        {
            TRUSTM_ENGINE_DBGFN("filename : %s\n",trustm_ctx.pubkeyfilename);
            //open 
            fp = fopen((const char *)trustm_ctx.pubkeyfilename,"r");
            if (!fp)
            {
                TRUSTM_ENGINE_ERRFN("failed to open file %s\n",trustm_ctx.pubkeyfilename);
                break;
            }
            PEM_read(fp, &name,&header,&data,(long int *)&len);
            //TRUSTM_ENGINE_DBGFN("name   : %s\n",name);
            //TRUSTM_ENGINE_DBGFN("len : %d\n",len);
            //trustmHexDump(data,len);
            if (!(strcmp(name,"PUBLIC KEY")))
            {
                trustm_ctx.pubkeylen = (uint16_t)len;
                for(i=0;i<len;i++)
                {
                    trustm_ctx.pubkey[i] = *(data+i);
                    //printf("%.x ",trustm_ctx.pubkey[i]);
                }
                key = d2i_PUBKEY(NULL,(const unsigned char **)&data,len);

                //trustmHexDump(trustm_ctx.pubkey,trustm_ctx.pubkeylen);
            }
        }
        
    }while(FALSE);
    trustm_ipc_release(&ssl_mutex);
    TRUSTM_ENGINE_DBGFN("<");
    return key;
}


static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ())
{
    int ret = TRUSTM_ENGINE_SUCCESS;

    TRUSTM_ENGINE_DBGFN(">");
    TRUSTM_ENGINE_DBGFN(">");
    TRUSTM_ENGINE_DBGFN("cmd: %d", cmd);

    do {
        //TRUSTM_ENGINE_MSGFN("Function Not implemented.");
        //Implement code here;
    }while(FALSE);
   
    TRUSTM_ENGINE_DBGFN("<");
    return ret;
    
}

static int engine_init(ENGINE *e)
{
    static int initialized = 0;

    int ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN("> Engine 0x%x init", (unsigned int) e);
    trustm_ipc_acquire(&ssl_mutex,"/ssl-mutex");
    do {
        TRUSTM_ENGINE_DBGFN("Initializing");
        if (initialized) {
            TRUSTM_ENGINE_DBGFN("Already initialized");
            ret = TRUSTM_ENGINE_SUCCESS;
            break;
        }
        me_util=NULL;
        me_crypt=NULL;
        pal_gpio_init(&optiga_reset_0);
        pal_gpio_init(&optiga_vdd_0);
        

        //Init TrustM context
        trustm_ctx.key_oid = 0x0000;
        trustm_ctx.rsa_key_type = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
        trustm_ctx.rsa_key_usage = OPTIGA_KEY_USAGE_AUTHENTICATION | OPTIGA_KEY_USAGE_ENCRYPTION;
        trustm_ctx.rsa_key_enc_scheme = OPTIGA_RSAES_PKCS1_V15;
        trustm_ctx.rsa_key_sig_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
        trustm_ctx.rsa_flag = TRUSTM_ENGINE_FLAG_NONE;
        
        trustm_ctx.ec_key_curve = OPTIGA_ECC_CURVE_NIST_P_256;
        trustm_ctx.ec_key_usage = OPTIGA_KEY_USAGE_AUTHENTICATION;
        trustm_ctx.ec_flag = TRUSTM_ENGINE_FLAG_NONE;
                
        trustm_ctx.pubkeyfilename[0] = '\0';
        trustm_ctx.pubkey[0] = '\0';
        trustm_ctx.pubkeylen = 0;
        trustm_ctx.pubkeyHeaderLen = 0;
        
        trustm_ctx.appOpen = 0;
        trustm_ctx.ipcInit = 0;

        // Init Random Method
#ifdef TRUSTM_RAND_ENABLED 
        ret = trustmEngine_init_rand(e);
        if (ret != TRUSTM_ENGINE_SUCCESS) {
            TRUSTM_ENGINE_ERRFN("Init Rand Fail!!");
            break;
        }
#endif

        // Init RSA Method
        ret = trustmEngine_init_rsa(e);
        if (ret != TRUSTM_ENGINE_SUCCESS) {
            TRUSTM_ENGINE_ERRFN("Init RSA Fail!!");
            break;
        }

        //Init EC Method
        ret = trustmEngine_init_ec(e);
        if (ret != TRUSTM_ENGINE_SUCCESS) {
        TRUSTM_ENGINE_ERRFN("Init EC Fail!!");
        break;
        }

        initialized = 1;
    }while(FALSE);
    trustm_ipc_release(&ssl_mutex);
    TRUSTM_ENGINE_DBGFN("<");
    return ret;
}

static int bind(ENGINE *e, const char *id)
{
    int ret = TRUSTM_ENGINE_FAIL;
    
    TRUSTM_ENGINE_DBGFN(">");
   

    do {         
        if (!ENGINE_set_id(e, engine_id)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_id failed\n");
            break;
        }
        if (!ENGINE_set_name(e, engine_name)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_name failed\n");
            break;
        }

        /* The init function is not allways called so we initialize crypto methods
           directly from bind. */
        if (!engine_init(e)) {
            TRUSTM_ENGINE_DBGFN("TrustM enigne initialization failed\n");
            break;
        }

        if (!ENGINE_set_load_privkey_function(e, engine_load_privkey)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_load_privkey_function failed\n");
            break;
        }
        
        if (!ENGINE_set_load_pubkey_function(e, engine_load_pubkey)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_load_pubkey_function failed\n");
            break;
        }

        
        if (!ENGINE_set_finish_function(e, engine_finish)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_finish_function failed\n");
            break;
        }

        if (!ENGINE_set_destroy_function(e, engine_destroy)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_destroy_function failed\n");
            break;
        }

        if (!ENGINE_set_ctrl_function(e, engine_ctrl)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_ctrl_function failed\n");
            break;
        }

/*
        if (!ENGINE_set_cmd_defns(e, engine_cmd_defns)) {
            TRUSTM_ENGINE_DBGFN("ENGINE_set_cmd_defns failed\n");
            break;
        }
*/
        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);
 
    TRUSTM_ENGINE_DBGFN("<");
    return ret;
  }

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
