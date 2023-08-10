/**
* MIT License
*
* Copyright (c) 2023 Infineon Technologies AG
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
#include <stdint.h>
#include <sys/time.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    
    uint16_t offset =0;
    uint32_t bytes_to_read;
    uint16_t optiga_oid = 0xE0C2;
    uint8_t read_data_buffer[27];


    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(-1);
    do
    {

            bytes_to_read = sizeof(read_data_buffer);
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_read_data(me_util,
                                                optiga_oid,
                                                offset,
                                                read_data_buffer,
                                                (uint16_t *)&bytes_to_read);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                for (int i=0; i < 10 ; i++)
                {
                    printf("%.2X",read_data_buffer[11+i]);
                }
            }
    } while(FALSE);

    // Capture OPTIGA Trust M error
    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    if (return_status != OPTIGA_LIB_SUCCESS)
    {
        return -1;
    }
    else {
        return 0;
    }

}
