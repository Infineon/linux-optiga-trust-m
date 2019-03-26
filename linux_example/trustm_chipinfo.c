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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

int main (int argc, char **argv)
{
	optiga_lib_status_t return_status;
	utrustm_UID_t UID;

	return_status = trustm_Open();
	if (return_status != OPTIGA_LIB_SUCCESS)
		exit(1);

	return_status = trustm_readUID(&UID);
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            printf("readUID [0xE0C2]: FAIL!!!\n");
        }
	else
	{
	    printf("Read Chip Info [0xE0C2]: Success.\n");
	    printf("===========================================\n");
        printf("CIM Identifier             [bCimIdentifer]: 0x%.2x\n", UID.st.bCimIdentifer);
	    printf("Platform Identifer   [bPlatformIdentifier]: 0x%.2x\n", UID.st.bPlatformIdentifier);
	    printf("Model Identifer         [bModelIdentifier]: 0x%.2x\n", UID.st.bModelIdentifier);
	    printf("ID of ROM mask                  [wROMCode]: 0x%.2x%.2x\n", 
								UID.st.wROMCode[0],
								UID.st.wROMCode[1]);
	    printf("Chip Type                    [rgbChipType]: 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
								UID.st.rgbChipType[0],
								UID.st.rgbChipType[1],
								UID.st.rgbChipType[2],
								UID.st.rgbChipType[3],
								UID.st.rgbChipType[4],
								UID.st.rgbChipType[5]);
	    printf("Batch Number              [rgbBatchNumber]: 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
								UID.st.rgbBatchNumber[0],
								UID.st.rgbBatchNumber[1],
								UID.st.rgbBatchNumber[2],
								UID.st.rgbBatchNumber[3],
								UID.st.rgbBatchNumber[4],
								UID.st.rgbBatchNumber[5]);
	    printf("X-coordinate              [wChipPositionX]: 0x%.2x%.2x\n", 
								UID.st.wChipPositionX[0],
								UID.st.wChipPositionX[1]);
	    printf("Y-coordinate              [wChipPositionY]: 0x%.2x%.2x\n",
								UID.st.wChipPositionY[0],
								UID.st.wChipPositionY[1]);
	    printf("Firmware Identifier [dwFirmwareIdentifier]: 0x%.2x%.2x%.2x%.2x\n", 
								UID.st.dwFirmwareIdentifier[0],
								UID.st.dwFirmwareIdentifier[1],
								UID.st.dwFirmwareIdentifier[2],
								UID.st.dwFirmwareIdentifier[3]);
	    printf("Build Number                 [rgbESWBuild]: %.2x %.2x\n",
								UID.st.rgbESWBuild[0],
								UID.st.rgbESWBuild[1]);
	}
	printf("\n");

	printf("Chip software build ");	
	if ((UID.st.rgbESWBuild[0] == 0x05) && (UID.st.rgbESWBuild[1] == 0x10))
		printf("V1.0.510\n");
	else if ((UID.st.rgbESWBuild[0] == 0x07) && (UID.st.rgbESWBuild[1] == 0x15))
		printf("V1.1.715\n");
	else if ((UID.st.rgbESWBuild[0] == 0x10) && (UID.st.rgbESWBuild[1] == 0x48))
		printf("V1.2.1048\n");
	else if ((UID.st.rgbESWBuild[0] == 0x11) && (UID.st.rgbESWBuild[1] == 0x12))
		printf("V1.30.1112\n");
	else if ((UID.st.rgbESWBuild[0] == 0x11) && (UID.st.rgbESWBuild[1] == 0x18))
		printf("V1.40.1118\n");
	else
		printf("Unknown\n");
	printf("===========================================\n");	


	trustm_Close();
	return 0;
}
