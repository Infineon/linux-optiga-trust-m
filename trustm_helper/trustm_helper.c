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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_timer.h"
#include "optiga/pal/pal_gpio.h"
#include "optiga/pal/pal_ifx_i2c_config.h"

#include "trustm_helper.h"

/*************************************************************************
*  Global
*************************************************************************/
optiga_util_t * me_util;
optiga_crypt_t * me_crypt;
optiga_lib_status_t optiga_lib_status;
uint16_t trustm_open_flag = 0;
uint8_t trustm_hibernate_flag = 0;
/*************************************************************************
*  functions
*************************************************************************/
/**
 * Callback when optiga_util_xxxx operation is completed asynchronously
 */

void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    TRUSTM_HELPER_DBGFN("optiga_lib_status: %x\n",optiga_lib_status);
}

/*************************************************************************
*  Read Metadata support
*************************************************************************/

static char __ALW[] = "ALW";
static char __CONF[] = "Conf";
static char __INT[] = "Int";
static char __LUC[] = "Luc";
static char __LCSG[] = "LcsG";
static char __LCSA[] = "LcsA";
static char __LCSO[] = "LcsO";
static char __EQ[] = "==";
static char __GT[] = ">";
static char __LT[] = "<";
static char __AND[] = "&&";
static char __OR[] = "||";
static char __NEV[] = "NEV";

static char __BSTR[] = "BSTR";
static char __UPCTR[] = "UPCTR";
static char __TA[] = "TA";
static char __DEVCERT[] = "DEVCERT";
static char __PRESSEC[] = "PRESSEC";
static char __PTFBIND[] = "PTFBIND";
static char __UPDATSEC[] = "UPDATSEC";

static char __ECC256[] = "ECC256";
static char __ECC384[] = "ECC384";
static char __RSA1024[] = "RSA1024";
static char __RSA2048[] = "RSA2048";
static char __SHA256[] = "SHA256";
static char __AUTH[] = "Auth";
static char __ENC[] = "Enc";
static char __HFU[] = "HFU";
static char __DM[] = "DM";
static char __SIGN[] = "Sign";
static char __AGREE[] = "Agreement";
static char __E1[100];

static void __delay (int cnt)
{
    uint32_t wait;
    
    
    for(wait=0;wait<(0x1fffffff*cnt);wait++)
    {}
}

/**********************************************************************
* trustm_readUID()
**********************************************************************/
static uint8_t __trustm_secCnt(void)
{
    uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[5];

    optiga_lib_status_t return_status;

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
            TRUSTM_HELPER_ERRFN("optiga_util_read_data : FAIL!!!\n");
            read_data_buffer[0] = 0;
            break;
        }

        while (OPTIGA_LIB_BUSY == optiga_lib_status) 
        {
            pal_os_timer_delay_in_milliseconds(10);
        }

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            read_data_buffer[0] = 0;
            break;
        }        

    } while(FALSE);

    return read_data_buffer[0];
}

static char* __decodeDataObj(uint8_t data)
{
    char *ret;
    switch (data)
    {
        case 0x00:
            ret = __BSTR; 
            break;
        case 0x01:
            ret = __UPCTR; 
            break;
        case 0x11:
            ret = __TA; 
            break;
        case 0x12:
            ret = __DEVCERT; 
            break;
        case 0x21:
            ret = __PRESSEC; 
            break;
        case 0x22:
            ret = __PTFBIND; 
            break;
        case 0x23:
            ret = __UPDATSEC; 
            break;
    }
    return ret;
}

static char* __decodeAC(uint8_t data)
{
    char *ret;
    switch (data)
    {
        case 0x00:
            ret = __ALW; 
            break;
        case 0x20:
            ret = __CONF; 
            break;
        case 0x21:
            ret = __INT; 
            break;
        case 0x40:
            ret = __LUC; 
            break;
        case 0x70:
            ret = __LCSG;
            break;
        case 0xE0:
            ret = __LCSA;
            break;
        case 0xE1:
            ret = __LCSO;
            break;
        case 0xFA:
            ret = __EQ;
            break;
        case 0xFB:
            ret = __GT;
            break;
        case 0xFC:
            ret = __LT;
            break;
        case 0xFD:
            ret = __AND;
            break;
        case 0xFE:
            ret = __OR;
            break;
        case 0xFF:
            ret = __NEV;
            break;
        case 0x03:
            ret = __ECC256;
            break;
        case 0x04:
            ret = __ECC384;
            break;
        case 0x41:
            ret = __RSA1024;
            break;
        case 0x42:
            ret = __RSA2048;
            break;
        case 0xE2:
            ret = __SHA256;
            break;
    }
    return ret;
}

static char* __decodeAC_E1(uint8_t data)
{
    char *ret;
    uint16_t i=0; 
    
    if (data & 0x01) // Auth = 0x01 
    {
        strcpy((__E1+i),__AUTH);
        i += (sizeof(__AUTH));
    }
    if (data & 0x02) // Enc = 0x02 
    {
        __E1[i-1] = '/';
        strcpy((__E1+i),__ENC);
        i += sizeof(__ENC);
    }
    if (data & 0x04) // HFU = 0x04 
    {
        __E1[i-1] = '/';
        strcpy((__E1+i),__HFU);
        i += sizeof(__HFU);
    }
    if (data & 0x08) // DM = 0x08 
    {
        __E1[i-1] = '/';
        strcpy((__E1+i),__DM);
        i += sizeof(__DM);
    }
    if (data & 0x10) // SIGN = 0x10 
    {
        __E1[i-1] = '/';
        strcpy((__E1+i),__SIGN);
        i += sizeof(__SIGN);
    }
    if (data & 0x20) // AGREE = 0x20 
    {
        __E1[i-1] = '/';
        strcpy((__E1+i),__AGREE);
        i += sizeof(__AGREE);
    }
    ret = __E1;
    return ret;
}

void trustmdecodeMetaData(uint8_t * metaData)
{
    uint16_t i,j;
    uint16_t metaLen;
    uint16_t len;
    uint8_t LcsO;
    uint16_t maxDataObjSize;
    
    if(*metaData == 0x20)
    {
        i = 1;
        metaLen = *(metaData+(i++));
        while(i < metaLen)
        {
            
            switch(*(metaData+(i++)))
            {
                case 0xC0:
                    // len is always 1
                    len = *(metaData+(i++));
                    LcsO = *(metaData+(i++));
                    printf("LcsO:0x%.2X, ",LcsO);
                    break;
                    
                case 0xC1:
                    // len is always 2
                    len = *(metaData+(i++));
                    printf("Ver:%.2x%.2x, ", *(metaData+(i+1)),*(metaData+(i+2)));
                    i++;
                    i++;
                    break;
                case 0xC4:
                    // len is 1 or 2
                    len = *(metaData+(i++));
                    maxDataObjSize = *(metaData+(i++));
                    if (len == 2)
                        maxDataObjSize = (maxDataObjSize<<8) + *(metaData+(i++));
                    printf("Max:%d, ",maxDataObjSize);
                    break;
                
                case 0xC5:
                    len = *(metaData+(i++));
                    maxDataObjSize = *(metaData+(i++));
                    if (len == 2)
                        maxDataObjSize = (maxDataObjSize<<8) + *(metaData+(i++));
                    printf("Used:%d, ",maxDataObjSize);
                    break;
                
                case 0xD0:
                case 0xD1:
                case 0xD3:
                    switch (*(metaData+i-1))
                    {
                        case 0xD0:
                            printf("C:");
                            break;
                        case 0xD1:
                            printf("R:");
                            break;
                        case 0xD3:
                            printf("E:");
                            break;
                    }
                    len = *(metaData+(i++));
                    for (j=0; j<len;j++)
                    {
                        switch(*(metaData+(i)))
                        {
                            case 0x00: // ALW
                            case 0xff: // NEV
                                printf("%s, ",__decodeAC(*(metaData+(i++))));
                                break;
                            case 0x20: // Conf
                            case 0x21: // Int
                            case 0x40: // Luc
                                printf("%s",__decodeAC(*(metaData+(i++))));
                                printf("-0x%.2X%.2X",*(metaData+(i)),*(metaData+(i+1)));
                                i += 2;
                                j += 2;
                                if ((len-j) < 3)
                                    printf(", ");                           
                                break;
                            case 0x70: // LcsG
                            case 0xe0: // LcsA
                            case 0xe1: // LcsO
                                printf("%s",__decodeAC(*(metaData+(i++))));
                                printf("%s",__decodeAC(*(metaData+(i++))));
                                printf("0x%.2X",*(metaData+(i++)));
                                j += 2;
                                if ((len-j) < 3)
                                    printf(", ");                           
                                break;
                            case 0xfa: // ==
                            case 0xfb: // >
                            case 0xfc: // <
                            case 0xfd: // &&
                            case 0xfe: // ||
                                printf("%s",__decodeAC(*(metaData+(i++))));
                                break;
                        }
                    }
                    break;
                    
                case 0xE0:
                    // len is always 1
                    len = *(metaData+(i++));
                    printf("Algo:%s, ",__decodeAC(*(metaData+(i++))));                
                    break;
                    
                case 0xE1:
                    // len is always 1
                    len = *(metaData+(i++));
                    printf("Key:%s, ",__decodeAC_E1(*(metaData+(i++))));                
                    break;
                
                case 0xE8:
                    //
                    len = *(metaData+(i++));
                    printf("DType:%s, ",__decodeDataObj(*(metaData+(i++))));                
                    break;
                    
                default:
                    i = metaLen;
                    break;
                    
            }
        }
    printf("\n");    
    }
}

optiga_lib_status_t trustmReadMetadata(uint16_t optiga_oid, trustm_metadata_t *oidMetadata)
{
    optiga_lib_status_t return_status;
    uint16_t bytes_to_read;
    uint8_t read_data_buffer[2048];
    uint16_t i,j;

    oidMetadata->metadataLen = 0;
    oidMetadata->D0_changeLen = 0;
    oidMetadata->D1_readLen = 0;
    oidMetadata->D3_executeLen = 0;
    oidMetadata->C4_maxSize = 0;
    oidMetadata->C5_used = 0;
        
    do
    {
        bytes_to_read = sizeof(read_data_buffer);
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_read_metadata(me_util,
                                                    optiga_oid,
                                                    read_data_buffer,
                                                    &bytes_to_read);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;          
        //Wait until the optiga_util_read_metadata operation is completed
        while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
        return_status = optiga_lib_status;
        if (return_status != OPTIGA_LIB_SUCCESS)
            break;
        else
        {
            if(read_data_buffer[0] == 0x20)
            {
                oidMetadata->metadataLen = read_data_buffer[1];
                for(i = 2; i < read_data_buffer[1];i += read_data_buffer[i+1]+2)
                {
                    switch(read_data_buffer[i])
                    {
                        case 0xC0:
                            oidMetadata->C0_lsc0 = read_data_buffer[i+2];
                            break;
                        case 0xC1:
                            oidMetadata->C1_verion[0] = read_data_buffer[i+1];
                            oidMetadata->C1_verion[1] = read_data_buffer[i+2];                    
                            break;
                        case 0xC4:
                            if (read_data_buffer[i+1] == 2)
                                oidMetadata->C4_maxSize = (uint16_t)((read_data_buffer[i+2] << 8)+read_data_buffer[i+3]);
                            else
                                oidMetadata->C4_maxSize = (uint16_t) read_data_buffer[i+2];                              
                            break;
                        case 0xC5:
                            if (read_data_buffer[i+1] == 2)
                                oidMetadata->C5_used = (uint16_t)((read_data_buffer[i+2] << 8)+read_data_buffer[i+3]);
                            else
                                oidMetadata->C5_used = (uint16_t) read_data_buffer[i+2]; 
                            break;
                        case 0xD0:
                            oidMetadata->D0_changeLen = read_data_buffer[i+1];
                            for(j=0;j<read_data_buffer[i+1];j++)
                                oidMetadata->D0_change[j] = read_data_buffer[i+2+j];                            
                            break;
                        case 0xD1:
                            oidMetadata->D1_readLen = read_data_buffer[i+1];
                            for(j=0;j<read_data_buffer[i+1];j++)
                                oidMetadata->D1_read[j] = read_data_buffer[i+2+j];                        
                            break;
                        case 0xD3:
                            oidMetadata->D3_executeLen = read_data_buffer[i+1];
                            for(j=0;j<read_data_buffer[i+1];j++)
                                oidMetadata->D3_execute[j] = read_data_buffer[i+2+j];
                            break;
                        case 0xE0:
                            oidMetadata->E0_algo = read_data_buffer[i+2];                        
                            break;
                        case 0xE1:
                            oidMetadata->E1_keyUsage = read_data_buffer[i+2];
                            break;
                        case 0xE8:
                            oidMetadata->E8_dataObjType = read_data_buffer[i+2];
                            break;
                        default:
                            i = bytes_to_read;
                            oidMetadata->metadataLen = 0;
                    }
                }
            }
        }        
    }while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);
        
    return return_status;
}

/**********************************************************************
* trustmHexDump()
**********************************************************************/
void trustmHexDump(uint8_t *pdata, uint32_t len)
{
    uint32_t i, j;

    printf("\t");    
    j=0;
    for (i=0; i < len; i++)
    {
        printf("%.2X ",*(pdata+i));
        if (j < 15)    
        {
            j++;
        }
        else
        {
            j=0;
            printf("\n\t");
        }
    }
    printf("\n");
}

uint16_t trustmWritePEM(uint8_t *buf, uint32_t len, const char *filename, char *name)
{
    FILE *fp;
    char header[] = "";

    fp = fopen(filename,"wb");
    if (!fp)
    {
        TRUSTM_HELPER_ERRFN("error creating file!!\n");
        return 1;
    }

    //Write cert to file
    PEM_write(fp, name,header,buf,(long int)len);                

    fclose(fp);

    return 0;
}

uint16_t trustmWriteDER(uint8_t *buf, uint32_t len, const char *filename)
{
    FILE *fp;

    fp = fopen(filename,"wb");
    if (!fp)
    {
        TRUSTM_HELPER_ERRFN("error creating file!!\n");
        return 1;
    }

    //Write cert to file
    fwrite(buf, 1, len, fp);                

    fclose(fp);

    return 0;
}

uint16_t trustmReadPEM(uint8_t *buf, uint32_t *len, const char *filename, char *name, uint16_t *keySize, uint16_t *keyType)
{
    FILE *fp;
    char *tempName;
    char *header;
    uint8_t *data;
    long int dataLen;

    EVP_PKEY *pkey;
    RSA *rsa_key;
    EC_KEY *ec_key;
    const EC_GROUP *ec_group;
    int i,j;

    fp = fopen(filename,"r");
    if (!fp)
    {
        TRUSTM_HELPER_ERRFN("failed to open file %s\n",filename);
        return 1;
    }
    
    pkey = PEM_read_PUBKEY(fp,NULL,NULL,NULL);
    i = EVP_PKEY_id(pkey);
    *keyType = (uint16_t) i;
    TRUSTM_HELPER_DBGFN("pkey id : %d [%X]\n",i,i);
    
    if((i == EVP_PKEY_RSA) ||(i == EVP_PKEY_RSA2) )
    {
        rsa_key = EVP_PKEY_get1_RSA(pkey);
        i = RSA_size(rsa_key) * 8;
        TRUSTM_HELPER_DBGFN("rsa len id : %d [%X]\n",i,i);
        
    } else if (i == EVP_PKEY_EC)
    {
        ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        ec_group = EC_KEY_get0_group(ec_key);
        i = EC_GROUP_order_bits(ec_group);
        TRUSTM_HELPER_DBGFN("ec len id : %d [%X]\n",i,i);
    }
    *keySize = (uint16_t) i;
    
    rewind(fp);
    dataLen = 0;
    PEM_read(fp, &tempName,&header,&data,&dataLen);
    if (dataLen != 0)
    {
        // Detecting Header
        i = 0;
        if (data[0] == 0x30) // First SEQUENCE
        {
            if (data[1] < 0x80) // Short Len
            {
                if(data[2] == 0x30) // Second SEQUENCE
                    i = data[3] + 4;
            } else // Long Len
            {
                j = (data[1] & 0x7f)+2;
                if(data[j] == 0x30) // Second SEQUENCE
                    i = data[j+1]+j+2;
            }
        }
        
        memcpy(buf,data+i,dataLen-i);    
        strcpy(name,tempName);
    }
    *len = dataLen-i;
   
    fclose(fp);
    return 0;
}

uint16_t trustmReadDER(uint8_t *buf, uint32_t *len, const char *filename)
{
    
    FILE *fp;
    uint16_t tempLen;
    uint8_t data[2048];

    //open 
    fp = fopen((const char *)filename,"rb");
    if (!fp)
    {
        return 1;
    }

    //Read file
    tempLen = fread(data, 1, sizeof(data), fp); 
    if (tempLen > 0)
    {
        memcpy(buf,data,tempLen);
        *len = tempLen;
    }
    else
    {
        *len = 0;
    }

    fclose(fp);

    return 0;
}

uint16_t trustmWriteX509PEM(X509 *x509, const char *filename)
{
    FILE *x509file;
    uint16_t ret;

    //create x509 file pem
    x509file = fopen(filename,"wb");
    if (!x509file)
    {
        TRUSTM_HELPER_ERRFN("error creating x509 file!!\n");
        return 1;
    }

    //Write cert to file
    ret = PEM_write_X509(x509file, x509);
    fclose(x509file);
    if (!ret)
    {
        TRUSTM_HELPER_ERRFN("Unable Cert to write to file!!\n");
        return 1;
    }

    return 0;

}

uint16_t trustmReadX509PEM(X509 **x509, const char *filename)
{
    FILE *x509file;

    //open x509 file pem
    x509file = fopen(filename,"rb");
    if (!x509file)
    {
        TRUSTM_HELPER_ERRFN("error reading x509 file!!\n");
        return 1;
    }

    //Read file to cert 
    *x509 = PEM_read_X509(x509file, NULL, 0, NULL);
    fclose(x509file);
    if (x509 == NULL)
    {
        TRUSTM_HELPER_ERRFN("Unable read cert from file!!\n");
        return 1;
    }

    return 0;

}


/**********************************************************************
* trustm_readUID()
**********************************************************************/
optiga_lib_status_t trustm_readUID(utrustm_UID_t *UID)
{
    uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[1024];

    optiga_lib_status_t return_status;

    uint16_t i;

    do
    {

        //Read device UID
        optiga_oid = 0xE0C2;
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
            TRUSTM_HELPER_ERRFN("optiga_util_read_data : FAIL!!!\n");
            break;
        }

        while (OPTIGA_LIB_BUSY == optiga_lib_status) 
        {
            pal_os_timer_delay_in_milliseconds(10);
        }

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //Reading metadata data object failed.
            break;
        }        

        for (i=0;i<bytes_to_read;i++)
        {
            UID->b[i] = read_data_buffer[i];
        }

    } while(FALSE);

    return return_status;
}

/**********************************************************************
* optiga_crypt_callback()
**********************************************************************/
void optiga_crypt_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}



/**********************************************************************
* trustm_Open()
**********************************************************************/
optiga_lib_status_t trustm_Open(void)
{
    optiga_lib_status_t return_status;

    TRUSTM_HELPER_DBGFN(">");
    trustm_open_flag = 0;
    do
    {
        pal_gpio_init(&optiga_reset_0);
        pal_gpio_init(&optiga_vdd_0);
        //Create an instance of optiga_util to open the application on OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (NULL == me_util)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_create\n");
            break;
        }
        TRUSTM_HELPER_DBGFN("TrustM util instance created. \n");

        me_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == me_crypt)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_crypt_create\n");
            break;
        }
        TRUSTM_HELPER_DBGFN("TrustM crypt instance created. \n");

        TRUSTM_HELPER_DBGFN("TrustM Open. \n");

        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */        
        optiga_lib_status = OPTIGA_LIB_BUSY;
        if ((access(TRUSTM_HIBERNATE_CTX_FILENAME,F_OK) != -1) &&
            (access(TRUSTM_CTX_FILENAME,F_OK) != -1) &&
            (trustm_hibernate_flag != 0))
        {
            TRUSTM_HELPER_DBGFN("Hibernate ctx found. Restore ctx\n");
            return_status = optiga_util_open_application(me_util, 1); // perform restore
        }
        else
        {
            TRUSTM_HELPER_DBGFN("No hibernate ctx found. Skip restore\n");
            return_status = optiga_util_open_application(me_util, 0); // skip restore
        }
        
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_open_application[1] \n");
            break;
        }


        TRUSTM_HELPER_DBGFN("waiting (max count: 50)");
        //Wait until the optiga_util_open_application is completed
        while (optiga_lib_status == OPTIGA_LIB_BUSY )
        {
            TRUSTM_HELPER_DBG(".");
            pal_os_timer_delay_in_milliseconds(50);
            //i++;
            //i++;
        }
        TRUSTM_HELPER_DBG("\n");
        TRUSTM_HELPER_DBGFN("count : %d \n",i);

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util open application failed
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_open_application \n");
            trustmPrintErrorCode(optiga_lib_status);
            return_status = optiga_lib_status;
            break;
        }
        
        trustm_open_flag = 1;
        TRUSTM_HELPER_DBGFN("Success : optiga_util_open_application \n");
    }while(FALSE);      



    TRUSTM_HELPER_DBGFN("<");
    return return_status;
}

/**********************************************************************
* trustX_Close()
**********************************************************************/
optiga_lib_status_t trustm_Close(void)
{
    optiga_lib_status_t return_status;
    uint8_t secCnt;

    TRUSTM_HELPER_DBGFN(">");

    do{
        if (trustm_open_flag != 1)
        {
            TRUSTM_HELPER_ERRFN("trustM is not open \n");
            break;
        }      

        if (trustm_hibernate_flag != 0)
        {
            if (access(TRUSTM_HIBERNATE_CTX_FILENAME,F_OK) != -1)
                remove(TRUSTM_HIBERNATE_CTX_FILENAME);

            secCnt = __trustm_secCnt();
            while (secCnt)
            {
                TRUSTM_HELPER_INFO("Security Event Counter : %d [waiting. Ctrl+c to abort.]\n",secCnt);
                __delay(2);
                secCnt = __trustm_secCnt();
                if (secCnt == 0)
                    TRUSTM_HELPER_INFO("context saved.\n");
            }
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_close_application(me_util, 1);
        }
        else
        {
            if (access(TRUSTM_HIBERNATE_CTX_FILENAME,F_OK) != -1)
                remove(TRUSTM_HIBERNATE_CTX_FILENAME);
            if (access(TRUSTM_CTX_FILENAME,F_OK) != -1)
                remove(TRUSTM_CTX_FILENAME);

            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_util_close_application(me_util, 0);
        }
            
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_close_application \n");
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
            //printf("Waiting : optiga_util_close_application \n");
            //printf(".");
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            TRUSTM_HELPER_ERRFN("Fail : optiga_util_close_application \n");
            return_status = optiga_lib_status;
            break;
        }

        trustm_open_flag = 0;
        pal_gpio_deinit(&optiga_reset_0);
        pal_gpio_deinit(&optiga_vdd_0);
        TRUSTM_HELPER_DBGFN("Success : optiga_util_close_application \n");

    }while(FALSE);

    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    // destroy util and crypt instances
    //optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = optiga_crypt_destroy(me_crypt);
    if(OPTIGA_LIB_SUCCESS != return_status)
    {
        TRUSTM_HELPER_ERRFN("Fail : optiga_crypt_destroy \n");
        //break;
    }


    if (me_util != NULL)
        optiga_util_destroy(me_util);    
    
    TRUSTM_HELPER_DBGFN("TrustM Closed.\n");
    TRUSTM_HELPER_DBGFN("<");
    return return_status;
}

uint32_t trustmHexorDec(const char *aArg)
{
    uint32_t value;

    if ((strncmp(aArg, "0x",2) == 0) ||(strncmp(aArg, "0X",2) == 0))
        sscanf(aArg,"%x",&value);
    else
        sscanf(aArg,"%d",&value);

    return value;
}

uint16_t trustmwriteTo(uint8_t *buf, uint32_t len, const char *filename)
{
    FILE *datafile;

    //create 
    datafile = fopen(filename,"wb");
    if (!datafile)
    {
        return 1;
    }

    //Write to file
    fwrite(buf, 1, len, datafile);
    fclose(datafile);

    return 0;

}

uint16_t trustmreadFrom(uint8_t *data, uint8_t *filename)
{
    
    FILE *datafile;
    uint16_t len;
    uint8_t buf[2048];
    uint16_t ret;

    //open 
    datafile = fopen((const char *)filename,"rb");
    if (!datafile)
    {
        printf("File open error!!!\n");
        return 0;
    }

    //Read file
    len = fread(buf, 1, sizeof(buf), datafile); 
    if (len > 0)
    {
        ret = len;
        memcpy(data,buf,len);
    }

    fclose(datafile);

    return ret;

}

void trustmPrintErrorCode(uint16_t errcode)
{
    switch (errcode)
    {
        // OPTIGA comms
        case OPTIGA_LIB_BUSY: // OPTIGA host library in busy state
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA host library in busy state");
            break;
        case OPTIGA_COMMS_ERROR: //OPTIGA comms API failed
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms API failed");
            break;
        case OPTIGA_COMMS_ERROR_INVALID_INPUT: //OPTIGA comms API called with invalid inputs
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms API called with invalid inputs");
            break;
        case OPTIGA_COMMS_ERROR_MEMORY_INSUFFICIENT: //OPTIGA comms API called with insufficient memory buffer
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms API called with insufficient memory buffer");
            break;
        case OPTIGA_COMMS_ERROR_STACK_MEMORY: //OPTIGA comms Protocol stack memory insufficient
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms Protocol stack memory insufficient");
            break;
        case OPTIGA_COMMS_ERROR_FATAL: //OPTIGA comms Protocol fatal error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms Protocol fatal error");
            break;           
        case OPTIGA_COMMS_ERROR_HANDSHAKE: //OPTIGA comms Presentation layer handshake error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms Presentation layer handshake error");
            break;  
        case OPTIGA_COMMS_ERROR_SESSION: //OPTIGA comms Presentation layer session error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA comms Presentation layer session error");
            break;
            
        // OPTIGA command
        case OPTIGA_CMD_ERROR: //OPTIGA command API failed
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA command API failed");
            break; 
        case OPTIGA_CMD_ERROR_INVALID_INPUT: //OPTIGA command API called with invalid inputs
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA command API called with invalid inputs");
            break; 
        case OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT: //OPTIGA command API called with insufficient memory buffer
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA command API called with insufficient memory buffer");
            break; 
            
        // OPTIGA util
        case OPTIGA_UTIL_ERROR: //OPTIGA util API failed
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA util API failed");
            break;         
        case OPTIGA_UTIL_ERROR_INVALID_INPUT: //OPTIGA util API called with invalid inputs
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA util API called with invalid inputs");
            break; 
        case OPTIGA_UTIL_ERROR_MEMORY_INSUFFICIENT: //OPTIGA util API called with insufficient memory buffer
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA util API called with insufficient memory buffer");
            break; 
        case OPTIGA_UTIL_ERROR_INSTANCE_IN_USE: //OPTIGA util API called when, a request of same instance is already in service
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA util API called when, a request of same instance is already in service");
            break;
            
        // OPTIGA crypt
        case OPTIGA_CRYPT_ERROR: //OPTIGA crypt API failed
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA crypt API failed");
            break;        
        case OPTIGA_CRYPT_ERROR_INVALID_INPUT: //OPTIGA crypt API called with invalid inputs
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA crypt API called with invalid inputs");
            break; 
        case OPTIGA_CRYPT_ERROR_MEMORY_INSUFFICIENT: //OPTIGA crypt API called with insufficient memory buffer
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA crypt API called with insufficient memory buffer");
            break; 
        case OPTIGA_CRYPT_ERROR_INSTANCE_IN_USE: //OPTIGA crypt API called when, a request of same instance is already in service
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA crypt API called when, a request of same instance is already in service");
            break; 
            
        // OPTIGA_DEVICE_ERROR (0x8000)
        case 0x8001: // OPTIGA device Invalid OID
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid OID");
            break; 
        case 0x8002: // OPTIGA device Invalid Password
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Password");
            break; 
        case 0x8003: // OPTIGA device Invalid Param Field
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Param Field");
            break; 
        case 0x8004: // OPTIGA device Invalid Length Field
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Length Field");
            break; 
        case 0x8005: // OPTIGA device Invalid Parameter In Data Field
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Parameter In Data Field");
            break; 
        case 0x8006: // OPTIGA device Internal Process Error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Internal Process Error");
            break; 
        case 0x8007: // OPTIGA device Access Condition Not Satisfied
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Access Condition Not Satisfied");
            break; 
        case 0x8008: // OPTIGA device Data Object Boundary Exceeded
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Data Object Boundary Exceeded");
            break; 
        case 0x8009: // OPTIGA device Metadata Truncation Error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Metadata Truncation Error");
            break; 
        case 0x800A: // OPTIGA device Invalid Command Field
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Command Field");
            break; 
        case 0x800B: // OPTIGA device Command Out Of Sequence
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Command Out Of Sequence");
            break; 
        case 0x800C: // OPTIGA device Command Not Available
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Command Not Available");
            break; 
        case 0x800D: // OPTIGA device Insufficient Buffer/Memory
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Insufficient Buffer/Memory");
            break; 
        case 0x800E: // OPTIGA device Counter Threshold Limit Exceeded
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Threshold Limit Exceeded");
            break; 
        case 0x800F: // OPTIGA device Invalid Manifest
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Manifest");
            break; 
        case 0x8010: // OPTIGA device Invalid/Wrong Payload Version
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid/Wrong Payload Version");
            break; 
        case 0x8021: // OPTIGA device Invalid Handshake Message
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Handshake Message");
            break; 
        case 0x8022: // OPTIGA device Version Mismatch
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Version Mismatch");
            break; 
        case 0x8023: // OPTIGA device Insufficient/Unsupported Cipher Suite
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Insufficient/Unsupported Cipher Suite");
            break; 
        case 0x8024: // OPTIGA device Unsupported Extension/Identifer
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Unsupported Extension/Identifer");
            break; 
        case 0x8026: // OPTIGA device Invalid Trust Anchor
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Trust Anchor");
            break; 
        case 0x8027: // OPTIGA device Trust Anchor Expired
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Trust Anchor Expired");
            break; 
        case 0x8028: // OPTIGA device Unsupported Trust Anchor
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Unsupported Trust Anchor");
            break; 
        case 0x8029: // OPTIGA device Invalid Certificate Format
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Invalid Certificate Format");
            break; 
        case 0x802A: // OPTIGA device Unsupported Certificate Algorithm
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Unsupported Certificate Algorithm");
            break; 
        case 0x802B: // OPTIGA device Cerificate Expired
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Cerificate Expired");
            break; 
        case 0x802C: // OPTIGA device Signature Verification Failure
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Signature Verification Failure");
            break; 
        case 0x802D: // OPTIGA device Integrity Validation Failure
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Integrity Validation Failure");
            break; 
        case 0x802E: // OPTIGA device Decryption Failure
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device Decryption Failure");
            break; 
        case 0x80FF: // OPTIGA device General Error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA device General Error");
            break; 
            
        // Unknown error
        default: // OPTIGA device Unknown Error
            TRUSTM_HELPER_RETCODEFN(errcode, "OPTIGA Unknown Error");
            break; 
    }   
}

void trustmGetOIDName(uint16_t optiga_oid, char *name)
{
    switch (optiga_oid)
    {
        case 0xE0C0:
            sprintf(name,"Global Life Cycle Status    [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C1:
            sprintf(name,"Global Security Status      [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C2:
            sprintf(name,"UID                         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C3:
            sprintf(name,"Sleep Mode Activation Delay [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C4:
            sprintf(name,"Current Limitation          [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C5:
            sprintf(name,"Security Event Counter      [0x%.4X] ", optiga_oid);
            break;
        case 0xE0C6:
            sprintf(name,"Max Com Buffer Size         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0E0:
            sprintf(name,"Device Public Key IFX       [0x%.4X] ", optiga_oid);
            break;
        case 0xE0E1:
        case 0xE0E2:
        case 0xE0E3:
            sprintf(name,"Device Public Key           [0x%.4X] ", optiga_oid);
            break;
        case 0xE0E8:
            sprintf(name,"Root CA Public Key Cert1    [0x%.4X] ", optiga_oid);
            break;
        case 0xE0E9:
            sprintf(name,"Root CA Public Key Cert2    [0x%.4X] ", optiga_oid);
            break;
        case 0xE0EF:
            sprintf(name,"Root CA Public Key Cert8    [0x%.4X] ", optiga_oid);
            break;
        case 0xE0F0:
            sprintf(name,"Device EC Privte Key 1         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0F1:
        case 0xE0F2:
        case 0xE0F3:
            sprintf(name,"Device EC Privte Key x         [0x%.4X] ", optiga_oid);
            break;
        case 0xE0FC:
        case 0xE0FD:
            sprintf(name,"Device RSA Privte Key x         [0x%.4X] ", optiga_oid);
            break;            
        case 0xE100:
        case 0xE101:
        case 0xE102:
        case 0xE103:
            sprintf(name,"Session Context x           [0x%.4X] ", optiga_oid);
            break;                    
        case 0xE120:
        case 0xE121:
        case 0xE122:
        case 0xE123:
            sprintf(name,"Monotonic Counter x         [0x%.4X] ", optiga_oid);
            break;
        case 0xE140:
            sprintf(name,"Shared Platform Binding Secret. [0x%.4x] ", optiga_oid);
            break;
        case 0xF1C0:
            sprintf(name,"Application Life Cycle Sts  [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1C1:
            sprintf(name,"Application Security Sts    [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1C2:
            sprintf(name,"Application Error Codes     [0x%.4X] ", optiga_oid);
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
            sprintf(name,"App DataStrucObj type 3     [0x%.4X] ", optiga_oid);
            break;                    
        case 0xF1E0:
        case 0xF1E1:
            sprintf(name,"App DataStrucObj type 2     [0x%.4X] ", optiga_oid);
            break;                        
        default:
            *name = 0x00;
            break;
    }    
}

