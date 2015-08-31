/* ***** BEGIN COPYRIGHT BLOCK *****
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * ***** END COPYRIGHT BLOCK ***** */

#include "string.h"
#include "cky_base.h"
#include "cky_factory.h"

/*
 * special commands can be issued at any time 
 */
CKYStatus
CKYAPDUFactory_SelectFile(CKYAPDU *apdu, CKYByte p1, CKYByte p2,
			  const CKYBuffer *AID)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_SELECT_FILE);
    CKYAPDU_SetP1(apdu, p1);
    CKYAPDU_SetP2(apdu, p2);
    return CKYAPDU_SetSendDataBuffer(apdu, AID);
}

CKYStatus
CKYAPDUFactory_SelectCardManager(CKYAPDU *apdu)
{
    CKYByte c = 0;
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_SELECT_FILE);
    CKYAPDU_SetP1(apdu, 0x04);
    CKYAPDU_SetP2(apdu, 0x00);
    /* I can't find the documentation for this, but if you pass an empty
     * AID to SelectFile on the Cyberflex Access 32k, it selects the
     * CardManager applet. Good thing, because I couldn't find any other
     * way to accomplish this without knowing the AID of the CardManager. */
    return CKYAPDU_SetSendData(apdu,&c,0);
}

/*
 * card manager commands must be issued with the card manager selected.
 */
CKYStatus
CKYAPDUFactory_GetCPLCData(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_GLOBAL_PLATFORM);
    CKYAPDU_SetINS(apdu, ISO_INS_GET_DATA);
    CKYAPDU_SetP1(apdu, 0x9f);
    CKYAPDU_SetP2(apdu, 0x7f);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_CPLCDATA);
}
/*
 * applet commands must be issued with the appplet selected.
 */
CKYStatus
CKYAPDUFactory_ListKeys(CKYAPDU *apdu, CKYByte sequence)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_LIST_KEYS);
    CKYAPDU_SetP1(apdu, sequence);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_LIST_KEYS);
}

CKYStatus
CKYAPDUFactory_ComputeCryptInit(CKYAPDU *apdu, CKYByte keyNumber, CKYByte mode,
				CKYByte direction, CKYByte location)
{
    CKYByte data[5];

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_CRYPT);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_INIT);
    data[0] = mode;
    data[1] = direction;
    data[2] = location;
    data[3] = 0;   /* future provide for init data */
    data[4] = 0;
    return CKYAPDU_SetSendData(apdu, data, sizeof(data));
}

CKYStatus
CKYAPDUFactory_ComputeCryptProcess(CKYAPDU *apdu, CKYByte keyNumber, 
				CKYByte location, const CKYBuffer *data)
{
    CKYStatus ret;
    CKYBuffer buf;

    CKYBuffer_InitEmpty(&buf);
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_CRYPT);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_PROCESS);
    if (data) {
	ret = CKYBuffer_Reserve(&buf, 3);
	if (ret != CKYSUCCESS) {
	    goto fail;
	}
	ret = CKYBuffer_AppendChar(&buf, location);
	if (ret != CKYSUCCESS) {
	    goto fail;
	}
	ret = CKYBuffer_AppendShort(&buf, (unsigned short)CKYBuffer_Size(data));
	if (ret != CKYSUCCESS) {
	    goto fail;
	} 
        ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
	if (ret != CKYSUCCESS) {
	    goto fail;
	} 
	ret = CKYAPDU_AppendSendDataBuffer(apdu, data);
    } else {
	ret = CKYAPDU_SetSendData(apdu, &location, 1);
    }
fail:
    CKYBuffer_FreeData(&buf);
    return ret;
}


CKYStatus
CKYAPDUFactory_ComputeCryptFinal(CKYAPDU *apdu, CKYByte keyNumber, 
		CKYByte location, const CKYBuffer *data, const CKYBuffer *sig)
{
    CKYStatus ret;
    CKYBuffer buf;

    CKYBuffer_InitEmpty(&buf);
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_CRYPT);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_FINAL);
    if (data) {
	ret = CKYBuffer_Reserve(&buf, 3);
	if (ret != CKYSUCCESS) {
	    goto fail;
	}
	ret = CKYBuffer_AppendChar(&buf, location);
	if (ret != CKYSUCCESS) {
	    goto fail;
	}
	ret = CKYBuffer_AppendShort(&buf, (unsigned short)CKYBuffer_Size(data));
	if (ret != CKYSUCCESS) {
	    goto fail;
	} 
        ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
	if (ret != CKYSUCCESS) {
	    goto fail;
	} 
	ret = CKYAPDU_AppendSendDataBuffer(apdu, data);
	if (ret != CKYSUCCESS) {
	    goto fail;
	} 
	if (sig) {
	    CKYBuffer_Resize(&buf,2);
	    CKYBuffer_SetShort(&buf, 0, (unsigned short)CKYBuffer_Size(sig));
	    ret = CKYAPDU_AppendSendDataBuffer(apdu, &buf);
	    if (ret != CKYSUCCESS) {
	    	goto fail;
	    } 
	    ret = CKYAPDU_AppendSendDataBuffer(apdu, sig);
	}
    } else {
	ret = CKYAPDU_SetSendData(apdu, &location, 1);
    }
fail:
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CKYAPDUFactory_ComputeECCKeyAgreementOneStep(CKYAPDU *apdu, CKYByte keyNumber,
                             CKYByte location,
                            const CKYBuffer *publicData, const CKYBuffer *secretKey)
{
    CKYStatus ret      = CKYINVALIDARGS;
    CKYSize   len;
    CKYBuffer buf;

    if (!publicData)
        return ret;

    if (!(len = CKYBuffer_Size(publicData)))
        return ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_ECC_KEY_AGREEMENT);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_ONE_STEP);

    CKYBuffer_InitEmpty(&buf);

    ret = CKYBuffer_Reserve(&buf, 3);

    if (ret == CKYSUCCESS)
        ret = CKYBuffer_AppendChar(&buf, location);
    if (ret == CKYSUCCESS)
        ret = CKYBuffer_AppendShort(&buf, (unsigned short)len);
    if (ret == CKYSUCCESS)
        ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
    if (ret == CKYSUCCESS)
        ret = CKYAPDU_AppendSendDataBuffer(apdu, publicData);
    if (ret == CKYSUCCESS && secretKey && 0 < (len = CKYBuffer_Size(secretKey))) {
        CKYBuffer_Resize(&buf,2);
        CKYBuffer_SetShort(&buf, 0, (unsigned short)len);
        ret = CKYAPDU_AppendSendDataBuffer(apdu, &buf);
        if (ret == CKYSUCCESS)
            ret = CKYAPDU_AppendSendDataBuffer(apdu, secretKey);
    }
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CKYAPDUFactory_ComputeCryptOneStep(CKYAPDU *apdu, CKYByte keyNumber, CKYByte mode,
				CKYByte direction, CKYByte location,
				const CKYBuffer *idata, const CKYBuffer *sig)
{
    CKYStatus ret      = CKYINVALIDARGS;
    CKYSize   len;
    CKYBuffer buf;

    if (!idata)
        return ret;

    if (!(len = CKYBuffer_Size(idata)) && location != CKY_DL_OBJECT)
        return ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_CRYPT);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_ONE_STEP);

    CKYBuffer_InitEmpty(&buf);

    ret = CKYBuffer_Reserve(&buf, 5);
    if (ret == CKYSUCCESS) 
	ret = CKYBuffer_AppendChar(&buf, mode);
    if (ret == CKYSUCCESS)
	ret = CKYBuffer_AppendChar(&buf, direction);
    if (ret == CKYSUCCESS)
	ret = CKYBuffer_AppendChar(&buf, location);
    if (ret == CKYSUCCESS)
	ret = CKYBuffer_AppendShort(&buf, (unsigned short)len);
    if (ret == CKYSUCCESS)
	ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
    if (ret == CKYSUCCESS)
	ret = CKYAPDU_AppendSendDataBuffer(apdu, idata);
    if (ret == CKYSUCCESS && sig && 0 < (len = CKYBuffer_Size(sig))) {
	CKYBuffer_Resize(&buf,2);
	CKYBuffer_SetShort(&buf, 0, (unsigned short)len);
	ret = CKYAPDU_AppendSendDataBuffer(apdu, &buf);
	if (ret == CKYSUCCESS)
	    ret = CKYAPDU_AppendSendDataBuffer(apdu, sig);
    }
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CKYAPDUFactory_CreatePIN(CKYAPDU *apdu, CKYByte pinNumber, CKYByte maxAttempts, 
						const char *pinValue)
{
    CKYSize len;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_CREATE_PIN);
    CKYAPDU_SetP1(apdu, pinNumber);
    CKYAPDU_SetP2(apdu, maxAttempts);
    len = strlen(pinValue);
    return CKYAPDU_SetSendData(apdu, (unsigned char *)pinValue, len);
}

CKYStatus
CKYAPDUFactory_VerifyPIN(CKYAPDU *apdu, CKYByte pinNumber, const char *pinValue)
{
    CKYSize len;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_VERIFY_PIN);
    CKYAPDU_SetP1(apdu, pinNumber);
    CKYAPDU_SetP2(apdu, 0x00);
    len = strlen(pinValue);
    return CKYAPDU_SetSendData(apdu, (unsigned char *)pinValue, len);
}

CKYStatus
CKYAPDUFactory_ChangePIN(CKYAPDU *apdu, CKYByte pinNumber, const char *oldPin, 
							const char *newPin)
{
    CKYSize oldLen, newLen;
    CKYBuffer buf;
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_CHANGE_PIN);
    CKYAPDU_SetP1(apdu, pinNumber);
    CKYAPDU_SetP2(apdu, 0x00);

    CKYBuffer_InitEmpty(&buf);
    oldLen = strlen(oldPin);
    newLen = strlen(newPin);
    /* optimization, do a single malloc for the whole block */
    ret = CKYBuffer_Reserve(&buf, oldLen+newLen+4);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendShort(&buf, (unsigned short)oldLen);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendData(&buf, (unsigned char *)oldPin, oldLen);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendShort(&buf, (unsigned short)newLen);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendData(&buf, (unsigned char *)newPin, newLen);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CKYAPDUFactory_ListPINs(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_LIST_PINS);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_LIST_PINS);
}

CKYStatus
CKYAPDUFactory_Logout(CKYAPDU *apdu, CKYByte pinNumber)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_LOGOUT);
    CKYAPDU_SetP1(apdu, pinNumber);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYSUCCESS;
}

CKYStatus
CKYAPDUFactory_CreateObject(CKYAPDU *apdu, unsigned long objectID, CKYSize size,
    unsigned short readACL, unsigned short writeACL, unsigned short deleteACL)
{
    CKYBuffer buf;
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_CREATE_OBJ);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    CKYBuffer_InitEmpty(&buf);
    /* optimization, do a single malloc for the whole block */
    ret = CKYBuffer_Reserve(&buf,0x0e);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendLong(&buf,objectID);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendLong(&buf,size);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendShort(&buf,readACL);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendShort(&buf,writeACL);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendShort(&buf,deleteACL);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;

}

CKYStatus
CKYAPDUFactory_DeleteObject(CKYAPDU *apdu, unsigned long objectID, CKYByte zero)
{
    CKYBuffer buf;
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_DELETE_OBJ);
    CKYAPDU_SetP1(apdu, zero);
    CKYAPDU_SetP2(apdu, 0x00);
    CKYBuffer_InitEmpty(&buf);
    ret = CKYBuffer_AppendLong(&buf,objectID);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;

}

CKYStatus
CKYAPDUFactory_ComputeECCSignatureOneStep(CKYAPDU *apdu, CKYByte keyNumber,
                             CKYByte location,
                            const CKYBuffer *idata, const CKYBuffer *sig)
{
    CKYStatus ret      = CKYINVALIDARGS;
    CKYSize   len;
    CKYBuffer buf;

    if (!idata)
        return ret;

    if (!(len = CKYBuffer_Size(idata)) && location != CKY_DL_OBJECT)
        return ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_COMPUTE_ECC_SIGNATURE);
    CKYAPDU_SetP1(apdu, keyNumber);
    CKYAPDU_SetP2(apdu, CKY_CIPHER_ONE_STEP);

    CKYBuffer_InitEmpty(&buf);

    ret = CKYBuffer_Reserve(&buf, 3);

    if (ret == CKYSUCCESS)
        ret = CKYBuffer_AppendChar(&buf, location);
    if (ret == CKYSUCCESS)
        ret = CKYBuffer_AppendShort(&buf, (unsigned short)len);
    if (ret == CKYSUCCESS)
        ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
    if (ret == CKYSUCCESS)
        ret = CKYAPDU_AppendSendDataBuffer(apdu, idata);
    if (ret == CKYSUCCESS && sig && 0 < (len = CKYBuffer_Size(sig))) {
        CKYBuffer_Resize(&buf,2);
        CKYBuffer_SetShort(&buf, 0, (unsigned short)len);
        ret = CKYAPDU_AppendSendDataBuffer(apdu, &buf);
        if (ret == CKYSUCCESS)
            ret = CKYAPDU_AppendSendDataBuffer(apdu, sig);
    }
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CKYAPDUFactory_ReadObject(CKYAPDU *apdu, unsigned long objectID, 
						CKYOffset offset, CKYByte size)
{
    CKYBuffer buf;
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_READ_OBJ);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    CKYBuffer_InitEmpty(&buf);
    /* optimization, do a single malloc for the whole block */
    ret = CKYBuffer_Reserve(&buf,0x09);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendLong(&buf,objectID);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendLong(&buf,offset);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, size);
    if (ret != CKYSUCCESS) {
	goto fail;
    }
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;

}

CKYStatus
CKYAPDUFactory_WriteObject(CKYAPDU *apdu, unsigned long objectID,
                                    CKYOffset offset,CKYSize size,CKYBuffer *data)
{
    CKYBuffer buf;
    CKYStatus ret = CKYSUCCESS;
    unsigned short dataSize = 0;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_WRITE_OBJ);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    CKYBuffer_InitEmpty(&buf);

    dataSize = (unsigned short) CKYBuffer_Size(data);

    if(!dataSize) {
        ret = CKYINVALIDARGS;
        goto fail;
    }

    ret = CKYBuffer_AppendLong(&buf,objectID);
    if (ret != CKYSUCCESS) {
        goto fail;
    }
    ret = CKYBuffer_AppendLong(&buf,offset);
    if (ret != CKYSUCCESS) {
        goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, size);
    if (ret != CKYSUCCESS) {
        goto fail;
    }

    ret = CKYAPDU_SetSendDataBuffer(apdu,&buf);

    if (ret != CKYSUCCESS) {
        goto fail;
    }

    ret = CKYAPDU_AppendSendDataBuffer(apdu, data);

    if (ret != CKYSUCCESS) {
        goto fail;
    }

fail:
    CKYBuffer_FreeData(&buf);
    return ret;

}

CKYStatus
CKYAPDUFactory_ListObjects(CKYAPDU *apdu, CKYByte sequence)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_LIST_OBJECTS);
    CKYAPDU_SetP1(apdu, sequence);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_LIST_OBJECTS);
}

CKYStatus
CKYAPDUFactory_GetStatus(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_STATUS);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_STATUS);
}

CKYStatus
CKYAPDUFactory_Noop(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_NOP);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYSUCCESS;
}

CKYStatus
CKYAPDUFactory_GetBuildID(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_BUILDID);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_BUILDID);
}

CKYStatus
CKYAPDUFactory_GetLifeCycle(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_LIFECYCLE);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_LIFE_CYCLE);
}

CKYStatus
CKYAPDUFactory_GetLifeCycleV2(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_LIFECYCLE);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_LIFE_CYCLE_V2);
}

CKYStatus
CKYAPDUFactory_GetRandom(CKYAPDU *apdu, CKYByte len)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_RANDOM);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, len);
}

CKYStatus
CKYAPDUFactory_SeedRandom(CKYAPDU *apdu, const CKYBuffer *data)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_SEED_RANDOM);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetSendDataBuffer(apdu, data);
}

CKYStatus
CKYAPDUFactory_GetIssuerInfo(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_ISSUER_INFO);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_ISSUER_INFO);
}

CKYStatus
CKYAPDUFactory_GetBuiltinACL(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
    CKYAPDU_SetINS(apdu, CKY_INS_GET_BUILTIN_ACL);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CKY_SIZE_GET_BUILTIN_ACL);
}

CKYStatus
CACAPDUFactory_SignDecrypt(CKYAPDU *apdu, CKYByte type, const CKYBuffer *data)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_SIGN_DECRYPT);
    CKYAPDU_SetP1(apdu, type);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetSendDataBuffer(apdu, data);
}

CKYStatus
CACAPDUFactory_GetCertificate(CKYAPDU *apdu, CKYSize size)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_GET_CERTIFICATE);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, size);
}

CKYStatus
CACAPDUFactory_ReadFile(CKYAPDU *apdu, unsigned short offset, 	
					CKYByte type, CKYByte count)
{
    CKYStatus ret;
    CKYBuffer buf;

    CKYBuffer_InitEmpty(&buf);
    CKYAPDU_SetCLA(apdu, CKY_CLASS_GLOBAL_PLATFORM);
    CKYAPDU_SetINS(apdu, CAC_INS_READ_FILE);
    CKYAPDU_SetP1(apdu, (offset >> 8) & 0xff);
    CKYAPDU_SetP2(apdu, offset & 0xff);
    ret = CKYBuffer_Reserve(&buf, 2);
    if (ret != CKYSUCCESS) {
	    goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, type);
    if (ret != CKYSUCCESS) {
	    goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, count);
    if (ret != CKYSUCCESS) {
	    goto fail;
    } 
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
CACAPDUFactory_GetProperties(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_GET_PROPERTIES);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CAC_SIZE_GET_PROPERTIES);
}

CKYStatus
PIVAPDUFactory_SignDecrypt(CKYAPDU *apdu, CKYByte chain, CKYByte alg, 
			   CKYByte key, int len, const CKYBuffer *data)
{
    CKYStatus ret;
    CKYAPDU_SetCLA(apdu, chain ? CKY_CLASS_ISO7816_CHAIN :
				  CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, PIV_INS_GEN_AUTHENTICATE);
    CKYAPDU_SetP1(apdu, alg);
    CKYAPDU_SetP2(apdu, key);
    ret =  CKYAPDU_SetSendDataBuffer(apdu, data);
    if (ret == CKYSUCCESS && chain == 0 && len != 0) {
	if (len >= 256) len = 0;
	ret = CKYAPDU_AppendReceiveLen(apdu, len);
    }
    return ret;
}

CKYStatus
PIVAPDUFactory_GetData(CKYAPDU *apdu, const CKYBuffer *object, CKYByte count)
{
    CKYStatus ret;
    CKYBuffer buf;
    CKYByte objectSize;

    CKYBuffer_InitEmpty(&buf);
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, 0xcb);
    CKYAPDU_SetP1(apdu, 0x3f);
    CKYAPDU_SetP2(apdu, 0xff);

    objectSize = CKYBuffer_Size(object);

    ret = CKYBuffer_Reserve(&buf, 2+objectSize);
    if (ret != CKYSUCCESS) {
	    goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, 0x5c);
    if (ret != CKYSUCCESS) {
	    goto fail;
    }
    ret = CKYBuffer_AppendChar(&buf, objectSize);
    if (ret != CKYSUCCESS) {
	    goto fail;
    } 
    ret = CKYBuffer_AppendCopy(&buf, object);
    if (ret != CKYSUCCESS) {
	    goto fail;
    } 
    ret = CKYAPDU_SetSendDataBuffer(apdu, &buf);
    if (ret != CKYSUCCESS) {
	    goto fail;
    } 
    ret = CKYAPDU_AppendReceiveLen(apdu, count);
fail:
    CKYBuffer_FreeData(&buf);
    return ret;
}

CKYStatus
P15APDUFactory_VerifyPIN(CKYAPDU *apdu, CKYByte keyRef, const CKYBuffer *pin)
{
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_VERIFY_PIN);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, keyRef);
    /* no pin, send an empty buffer */
    if (CKYBuffer_Size(pin) == 0) {
    	return CKYAPDU_SetReceiveLen(apdu, 0);
    }

    /* all CAC pins are 8 bytes exactly. If to long, truncate it */
    ret = CKYAPDU_SetSendDataBuffer(apdu, pin);
    return ret;

}

CKYStatus
P15APDUFactory_ReadRecord(CKYAPDU *apdu, CKYByte record, CKYByte short_ef, 
					CKYByte flags, CKYByte count)
{
    CKYByte control;

    control = (short_ef << 3) & 0xf8;
    control |= flags & 0x07;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_READ_RECORD);
    CKYAPDU_SetP1(apdu, record);
    CKYAPDU_SetP2(apdu, control);
    return CKYAPDU_SetReceiveLen(apdu, count);
}

CKYStatus
P15APDUFactory_ReadBinary(CKYAPDU *apdu, unsigned short offset, 
			CKYByte short_ef, CKYByte flags, CKYByte count)
{
    CKYByte p1 = 0,p2 = 0;
    unsigned short max_offset = 0;

    if (flags & P15_USE_SHORT_EF) {
	max_offset = 0xff;
	p1 = P15_USE_SHORT_EF | (short_ef & 0x7);
	p2 = offset & 0xff;
    } else {
	max_offset = 0x7fff;
	p1 = (offset >> 8) & 0x7f;
	p2 = offset & 0xff;
    }
    if (offset > max_offset) {
	return CKYINVALIDARGS;
    }

    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_READ_BINARY);
    CKYAPDU_SetP1(apdu, p1);
    CKYAPDU_SetP2(apdu, p2);
    return CKYAPDU_SetReceiveLen(apdu, count);
}

CKYStatus
P15APDUFactory_ManageSecurityEnvironment(CKYAPDU *apdu, CKYByte p1, CKYByte p2,
					CKYByte keyRef)
{
    CKYByte param[3];

    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_MANAGE_SECURITY_ENVIRONMENT);
    CKYAPDU_SetP1(apdu, p1);
    CKYAPDU_SetP2(apdu, p2);
    param[0] = 0x83;
    param[1] = 1;
    param[2] = keyRef;
    return CKYAPDU_SetSendData(apdu, param, sizeof param);
}

CKYStatus
P15APDUFactory_PerformSecurityOperation(CKYAPDU *apdu, CKYByte dir,
			int chain, CKYSize retLen, const CKYBuffer *data)
{
    CKYByte p1,p2;
    CKYStatus ret;

    CKYAPDU_SetCLA(apdu, chain ? CKY_CLASS_ISO7816_CHAIN :
				  CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, ISO_INS_PERFORM_SECURITY_OPERATION);
    if (dir == CKY_DIR_DECRYPT) {
	p1 = ISO_PSO_DECRYPT_P1;
	p2 = ISO_PSO_DECRYPT_P2;
    } else {
	p1 = ISO_PSO_SIGN_P1;
	p2 = ISO_PSO_SIGN_P2;
    }
    CKYAPDU_SetP1(apdu, p1);
    CKYAPDU_SetP2(apdu, p2);
    ret =  CKYAPDU_SetSendDataBuffer(apdu, data);
    if (ret == CKYSUCCESS && (chain == 0) && retLen != 0) {
	ret = CKYAPDU_AppendReceiveLength(apdu, retLen);
    }
    return ret;
}


