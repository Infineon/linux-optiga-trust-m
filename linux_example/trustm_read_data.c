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
#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

int main (int argc, char **argv)
{
	optiga_lib_status_t return_status;
	uint16_t i, skip_flag;
	
	uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[1024];

	return_status = trustm_Open();
	if (return_status != OPTIGA_LIB_SUCCESS)
		exit(1);

	do
	{
		printf("========================================================\n"); 	

		for (i = 0; i < (0xF200-0xE0C0-1); i++) 
		{
			optiga_oid = 0xE0C0;
			offset = 0x00;
			skip_flag = 0;	
			optiga_oid += i;
			switch (optiga_oid)
			{
				case 0xE0E0:
					printf("Device Public Key IFX       [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;
				case 0xE0E1:
				case 0xE0E2:
				case 0xE0E3:
					printf("Device Public Key           [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;
				case 0xE0E8:
					printf("Root CA Public Key Cert1    [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;
				case 0xE0E9:
					printf("Root CA Public Key Cert2    [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;
				case 0xE0EF:
					printf("Root CA Public Key Cert8    [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;	
				case 0xE120:
				case 0xE121:
				case 0xE122:
				case 0xE123:
					printf("Monotonic Counter x         [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;
				case 0xE140:
					printf("Shared Platform Binding Secert. [0x%.4x] ", optiga_oid);
					skip_flag = 1;
					break;	
				case 0xF1D0:
				case 0xF1D1:
				case 0xF1D2:
				case 0xF1D3:
				case 0xF1D4:
				case 0xF1D5:
				case 0xF1D6:
				case 0xF1D7:
				case 0xF1D8:
				case 0xF1D9:
				case 0xF1DA:
				case 0xF1DB:
					printf("App DataStrucObj type 1     [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;					
				case 0xF1E0:
				case 0xF1E1:
					printf("App DataStrucObj type 2     [0x%.4X] ", optiga_oid);
					skip_flag = 1;
					break;						
				default:
					skip_flag = 2;
					break;
			}

			if(skip_flag == 0 || skip_flag == 1)
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
				while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
				return_status = optiga_lib_status;
				if (return_status != OPTIGA_LIB_SUCCESS)
					break;
				else
				{
					printf("[Size %.4d] : \n", bytes_to_read);
					trustmHexDump(read_data_buffer,bytes_to_read);
				} // End of if
			} // End of if
		} // End of for loop
	}while(FALSE);
	
    // Capture OPTIGA Trust M error
	if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);
        
    printf("========================================================\n"); 	
	trustm_Close();

	return 0;
}
