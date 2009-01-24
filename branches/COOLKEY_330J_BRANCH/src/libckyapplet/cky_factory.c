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
CKYAPDUFactory_SelectFile(CKYAPDU *apdu, const CKYBuffer *AID)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CKY_INS_SELECT_FILE);
    CKYAPDU_SetP1(apdu, 0x04);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetSendDataBuffer(apdu, AID);
}

CKYStatus
CKYAPDUFactory_SelectCardManager(CKYAPDU *apdu)
{
    CKYByte c = 0;
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CKY_INS_SELECT_FILE);
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
    CKYAPDU_SetINS(apdu, CKY_INS_GET_DATA);
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
CKYAPDUFactory_ComputeCryptOneStep(CKYAPDU *apdu, CKYByte keyNumber, CKYByte mode,
				CKYByte direction, CKYByte location,
				const CKYBuffer *idata, const CKYBuffer *sig)
{
    CKYStatus ret      = CKYINVALIDARGS;
    CKYSize   len;
    CKYBuffer buf;

    if (!idata || !(len = CKYBuffer_Size(idata)) || location != CKY_DL_APDU)
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

/* Future add WriteObject */

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
CACAPDUFactory_SignDecrypt(CKYAPDU *apdu, const CKYBuffer *data)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_SIGN_DECRYPT);
    CKYAPDU_SetP1(apdu, 0x00);
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
CACAPDUFactory_GetProperties(CKYAPDU *apdu)
{
    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_GET_PROPERTIES);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    return CKYAPDU_SetReceiveLen(apdu, CAC_SIZE_GET_PROPERTIES);
}

CKYStatus
CACAPDUFactory_VerifyPIN(CKYAPDU *apdu, const char *pin)
{
    CKYStatus ret;
    CKYSize size;

    CKYAPDU_SetCLA(apdu, CKY_CLASS_ISO7816);
    CKYAPDU_SetINS(apdu, CAC_INS_VERIFY_PIN);
    CKYAPDU_SetP1(apdu, 0x00);
    CKYAPDU_SetP2(apdu, 0x00);
    /* no pin, send an empty buffer */
    if (!pin) {
    	return CKYAPDU_SetReceiveLen(apdu, 0);
    }

    /* all CAC pins are 8 bytes exactly. If to long, truncate it */
    size = strlen(pin);
    if (size > 8) {
	size = 8;
    }
    ret = CKYAPDU_SetSendData(apdu, (unsigned char *) pin, size);
    /* if too short, pad it */
    if ((ret == CKYSUCCESS) && (size < 8)) {
	static const unsigned char pad[]= { 0xff , 0xff, 0xff ,0xff, 
				   0xff, 0xff, 0xff, 0xff };
	return CKYAPDU_AppendSendData(apdu, pad, 8-size);
    }
    return ret;

}
