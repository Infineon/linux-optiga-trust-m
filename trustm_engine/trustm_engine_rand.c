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
#include <openssl/engine.h>

#include "trustm_helper.h"

#include "trustm_engine_common.h"

#ifdef WORKAROUND
	extern void pal_os_event_disarm(void);
	extern void pal_os_event_arm(void);
#endif

static int trustmEngine_getrandom(unsigned char *buf, int num);
static int trustmEngine_rand_status(void);


// OpenSSL random method define
static RAND_METHOD rand_methods = {
    NULL,                    // seed()
    trustmEngine_getrandom,
    NULL,                    // cleanup()
    NULL,                    // add()
    NULL,                // pseudorand()
    trustmEngine_rand_status        // status()
};

/** Return the entropy status of the prng
 * Since we provide real randomness 
 * function, our status is allways good.
 * @retval 1 allways good status
 */
static int trustmEngine_rand_status(void)
{
    return TRUSTM_ENGINE_SUCCESS;
}

/** Initialize the trusttm rand 
 *
 * @param e The engine context.
 */
uint16_t trustmEngine_init_rand(ENGINE *e)
{
    uint16_t ret = TRUSTM_ENGINE_FAIL;
    TRUSTM_ENGINE_DBGFN(">");
    
    ret = ENGINE_set_RAND(e, &rand_methods);
    
    TRUSTM_ENGINE_DBGFN("<");
    return ret;
    
}

/** Genereate random values
 * @param buf The buffer to write the random values to
 * @param num The amound of random bytes to generate
 * @retval 1 on success
 * @retval 0 on failure
 */
static int trustmEngine_getrandom(unsigned char *buf, int num)
{
    #define MAX_RAND_INPUT 256
    
    optiga_lib_status_t return_status;
    int i,j,k;
    uint8_t tempbuf[MAX_RAND_INPUT];    
    int ret = TRUSTM_ENGINE_FAIL;
    
    TRUSTM_ENGINE_DBGFN("> num : %d", num);
    
    i = num % MAX_RAND_INPUT; // max random number output, find the reminder
    j = (num - i)/MAX_RAND_INPUT; // Get the count 

#ifdef WORKAROUND		
    pal_os_event_arm();
#endif
  
    do 
    {    
        k = 0;
        if(i > 0)  
        {
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_random(me_crypt, 
                                OPTIGA_RNG_TYPE_TRNG, 
                                tempbuf,
                                MAX_RAND_INPUT);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;			
            //Wait until the optiga_util_read_metadata operation is completed
            while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;

            for (k=0;k<i;k++)
            {
                *(buf+k) = tempbuf[k]; 
            }
        }

        for(;j>0;j--)  
        {
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_random(me_crypt, 
                                OPTIGA_RNG_TYPE_TRNG, 
                                (buf+k),
                                MAX_RAND_INPUT);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;			
            //Wait until the optiga_util_read_metadata operation is completed
            while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            k += (MAX_RAND_INPUT);
        }

        ret = TRUSTM_ENGINE_SUCCESS;
    }while(FALSE);

	// Capture OPTIGA Error
	if (return_status != OPTIGA_LIB_SUCCESS)
		trustmPrintErrorCode(return_status);
  
    // if fail returns all zero
    if (ret != TRUSTM_ENGINE_SUCCESS)
    {
        TRUSTM_ENGINE_DBGFN("error ret 0!!!\n");
        for(i=0;i<num;i++)
        {
            *(buf+i) = 0;
        }
    }
    
    TRUSTM_ENGINE_DBGFN("length : %d\n",num);
    trustmHexDump(buf,num);    
    
#ifdef WORKAROUND    
	pal_os_event_disarm();	
#endif    
    
    TRUSTM_ENGINE_DBGFN("<");    
    return ret;
    #undef MAX_RAND_INPUT
}
