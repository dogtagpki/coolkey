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

#include <stdio.h>
#include "cky_applet.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/*****************************************************************
 *
 * Generic factorys are used by the generic APDU processing
 * to customize the formatting of APDU. Typically APDUs are formatted
 * using parameterized calls of the form CKYAPDUFactory_ADPUNAME.
 * The generic processing code, however needs calls with a common
 * Signature. To accomplish the conversion, we build generic versions
 * which take a void * parameter. Trivial APDU's can pass NULL or a pointer
 * to the single parameter that they need. More complicated APDU's use
 * CKYAppletArg* data structures defined above to pass more arguments.
 *
 * Generic factorys then call the standard CKYAPDUFactor_ADPUNAME() functions
 * to build the APDUs. These functions are intended only as arguments
 * to the generic ADPU calls, and not to be called directly.
 *
 *****************************************************************/
CKYStatus
CKYAppletFactory_SelectFile(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_SelectFile(apdu,(const CKYBuffer *)param);
}

CKYStatus
CKYAppletFactory_SelectCardManager(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_SelectCardManager(apdu);
}

CKYStatus
CKYAppletFactory_GetCPLCData(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetCPLCData(apdu);
}

CKYStatus
CKYAppletFactory_ListKeys(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_ListKeys(apdu, *( CKYByte *)param);
}

CKYStatus
CKYAppletFactory_ComputeCryptInit(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgComputeCrypt *ccs=(const CKYAppletArgComputeCrypt *)param;
    return CKYAPDUFactory_ComputeCryptInit(apdu, ccs->keyNumber, ccs->mode,
			ccs->direction, ccs->location);
					
}

CKYStatus
CKYAppletFactory_ComputeCryptProcess(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgComputeCrypt *ccs=(const CKYAppletArgComputeCrypt *)param;
    return CKYAPDUFactory_ComputeCryptProcess(apdu, ccs->keyNumber,
						ccs->location, ccs->data);
					
}

CKYStatus
CKYAppletFactory_ComputeCryptFinal(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgComputeCrypt *ccs=(const CKYAppletArgComputeCrypt *)param;
    return CKYAPDUFactory_ComputeCryptFinal(apdu, ccs->keyNumber, 
                               ccs->location, ccs->data, ccs->sig);
}

CKYStatus
CKYAppletFactory_ComputeCryptOneStep(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgComputeCrypt *ccs=(const CKYAppletArgComputeCrypt *)param;
    return CKYAPDUFactory_ComputeCryptOneStep(apdu, ccs->keyNumber,ccs->mode,
			ccs->direction, ccs->location, ccs->data, ccs->sig);
}

CKYStatus
CKYAppletFactory_CreatePIN(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgCreatePIN *cps = (const CKYAppletArgCreatePIN *)param;
    return CKYAPDUFactory_CreatePIN(apdu, cps->pinNumber, cps->maxAttempts,
						cps->pinValue);
}

CKYStatus
CKYAppletFactory_VerifyPIN(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgVerifyPIN *vps = (const CKYAppletArgVerifyPIN *)param;
    return CKYAPDUFactory_VerifyPIN(apdu, vps->pinNumber, vps->pinValue);
}

CKYStatus
CKYAppletFactory_ChangePIN(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgChangePIN *cps = (const CKYAppletArgChangePIN *)param;
    return CKYAPDUFactory_ChangePIN(apdu, cps->pinNumber, cps->oldPin,
							cps->newPin);
}

CKYStatus
CKYAppletFactory_ListPINs(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_ListPINs(apdu);
}

CKYStatus
CKYAppletFactory_Logout(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_Logout(apdu, *(const CKYByte *)param);
}

/* Future add WriteObject */

CKYStatus
CKYAppletFactory_CreateObject(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgCreateObject *cos=(const CKYAppletArgCreateObject *)param;
    return CKYAPDUFactory_CreateObject(apdu, cos->objectID, cos->size,
        		cos->readACL, cos->writeACL, cos->deleteACL);
}

CKYStatus
CKYAppletFactory_DeleteObject(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgDeleteObject *dos=(const CKYAppletArgDeleteObject *)param;
    return CKYAPDUFactory_DeleteObject(apdu, dos->objectID, dos->zero);

}

CKYStatus
CKYAppletFactory_ReadObject(CKYAPDU *apdu, const void *param)
{
    const CKYAppletArgReadObject *ros = (const CKYAppletArgReadObject *)param;
    return CKYAPDUFactory_ReadObject(apdu, ros->objectID,
						ros->offset, ros->size);
}

CKYStatus
CKYAppletFactory_ListObjects(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_ListObjects(apdu, *(const CKYByte *)param);
}

CKYStatus
CKYAppletFactory_GetStatus(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetStatus(apdu);
}

CKYStatus
CKYAppletFactory_Noop(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_Noop(apdu);
}

CKYStatus
CKYAppletFactory_GetBuildID(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetBuildID(apdu);
}

CKYStatus
CKYAppletFactory_GetLifeCycle(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetLifeCycle(apdu);
}

CKYStatus
CKYAppletFactory_GetLifeCycleV2(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetLifeCycleV2(apdu);
}

CKYStatus
CKYAppletFactory_GetRandom(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetRandom(apdu, *(CKYByte *)param);
}

CKYStatus
CKYAppletFactory_SeedRandom(CKYAPDU *apdu, const void *param)
{
    const CKYBuffer *buf=(CKYBuffer *)param;
    return CKYAPDUFactory_SeedRandom(apdu, buf);
}

CKYStatus
CKYAppletFactory_GetIssuerInfo(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetIssuerInfo(apdu);
}

CKYStatus
CKYAppletFactory_GetBuiltinACL(CKYAPDU *apdu, const void *param)
{
    return CKYAPDUFactory_GetBuiltinACL(apdu);
}

CKYStatus
CACAppletFactory_SignDecrypt(CKYAPDU *apdu, const void *param)
{
    const CKYBuffer *buf=(CKYBuffer *)param;
    return CACAPDUFactory_SignDecrypt(apdu, buf);
}

CKYStatus
CACAppletFactory_VerifyPIN(CKYAPDU *apdu, const void *param)
{
    const char *pin=(const char *)param;
    return CACAPDUFactory_VerifyPIN(apdu, pin);
}

CKYStatus
CACAppletFactory_GetCertificate(CKYAPDU *apdu, const void *param)
{
    CKYSize *size=(CKYSize*)param;
    return CACAPDUFactory_GetCertificate(apdu, *size);
}

CKYStatus
CACAppletFactory_GetProperties(CKYAPDU *apdu, const void *param)
{
    return CACAPDUFactory_GetProperties(apdu);
}

/*
 * deprecates 0.x functions
 */
CKYStatus
CKYAppletFactory_LogoutAllV0(CKYAPDU *apdu, const void *param)
{
   CKYByte data[2] = { 0, 0};
   CKYAPDU_SetCLA(apdu, CKY_CLASS_COOLKEY);
   CKYAPDU_SetINS(apdu, CKY_INS_LOGOUT_ALL);
   CKYAPDU_SetP1(apdu, 0x00);
   CKYAPDU_SetP2(apdu, 0x00);
   return CKYAPDU_SetSendData(apdu, data, sizeof(data));
}

/*****************************************************************
 *
 * Generic Fill routines used by several calls in common
 * and globally accessible
 *
 *****************************************************************/

/* a null fill function for those APDU's which do not return data */
CKYStatus
CKYAppletFill_Null(const CKYBuffer *response, CKYSize size, void *param)
{
    return CKYSUCCESS;
}

/* a Buffer Replace fill function for those APDU's which return unformated
 * chunks of data */
CKYStatus
CKYAppletFill_ReplaceBuffer(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYBuffer *buf = (CKYBuffer *)param;

    if (buf == NULL) {
	return CKYSUCCESS;
    }
    return CKYBuffer_Replace(buf, 0, CKYBuffer_Data(response),
					 CKYBuffer_Size(response) -2);
}

/* a Buffer Append fill function. Can be used with any APDU that uses Buffer
 * Replace. Repeated calls continuously fill the buffer. Most useful for read.
 */
CKYStatus
CKYAppletFill_AppendBuffer(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYBuffer *buf = (CKYBuffer *)param;

    return CKYBuffer_AppendData(buf, CKYBuffer_Data(response), 
						CKYBuffer_Size(response) -2);
}

CKYStatus
CKYAppletFill_Byte(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYByte *v = (CKYByte *)param;

    *v = CKYBuffer_GetChar(response, 0);
    return CKYSUCCESS;
}

CKYStatus
CKYAppletFill_Short(const CKYBuffer *response, CKYSize size, void *param)
{
    unsigned short *v = (unsigned short *)param;

    *v = CKYBuffer_GetShort(response, 0);
    return CKYSUCCESS;
}

CKYStatus
CKYAppletFill_Long(const CKYBuffer *response, CKYSize size, void *param)
{
    unsigned long *v = (unsigned long *)param;

    *v = CKYBuffer_GetLong(response, 0);
    return CKYSUCCESS;
}

/*****************************************************************
 *
 * Utilities shared by all the fetch Cards.
 *
 *****************************************************************/
/*
 * verify the we got a successful response. Responses should include
 * the expected data returned plus a 2 byte return code. This return
 * code should be 0x9000 on success.
 */
CKYBool
CKYApplet_VerifyResponse(const CKYBuffer *buf, CKYSize dataSize,
						    CKYISOStatus *apduRC) {
    CKYSize size = CKYBuffer_Size(buf);
    CKYISOStatus rc = CKYISO_INVRESPONSE;
    CKYBool valid = 0;

    /* is there enough size for the return code ? */
    if (size < 2) {
	goto done;
    }
    /* fetch the data */
    rc = CKYBuffer_GetShort(buf, size-2);

    /* is there enough size for the expected data ? */
    if ((dataSize != CKY_SIZE_UNKNOWN) && (size != dataSize+2)) {
	goto done;
    }

    /* did we return successfully? */
    valid = (rc == CKYISO_SUCCESS) || ((rc & CKYISO_MORE_MASK) == CKYISO_MORE);

done:	
    if (apduRC) {
	*apduRC = rc;
    }
    return valid;
}


/*
 * most commands have identical operations. Isolate the differences in
 * call back functions, and create a generic APDU handler which Creates
 * APDU's, Does the exchange, and fills in the results.
 */
CKYStatus
CKYApplet_HandleAPDU(CKYCardConnection *conn, 
 		CKYAppletFactory afFunc, const void *afArg, 
		const CKYBuffer *nonce, CKYSize size,
		CKYFillFunction fillFunc, void *fillArg, CKYISOStatus *apduRC)
{
    CKYAPDU apdu;
    CKYBuffer response;
    CKYStatus ret;

    if (apduRC) {
	*apduRC = CKYISO_NORESPONSE;
    }

    /* initialize the response and APDU buffers */
    CKYBuffer_InitEmpty(&response);
    ret = CKYAPDU_Init(&apdu);
    if (ret != CKYSUCCESS) {
	goto done;
    }

    /* fill in the APDU buffer with the correct values */
    ret = (*afFunc)(&apdu, afArg);
    if (ret != CKYSUCCESS) {
	goto done;
    }
    /* if NONCE supplied, add it to the end of the apdu */
    if (nonce) {
	/*
	 * Local Secured commands need the nonce returned from Login to
	 * verify that they are valid. Nonce's are just added to the end
	 * of the APDU much like
	 */
	ret = CKYAPDU_AppendSendDataBuffer(&apdu, nonce);
	if (ret != CKYSUCCESS) {
	    goto done;
	}
    }

    /* send it to the card */
    ret = CKYCardConnection_ExchangeAPDU(conn, &apdu, &response);
    if (ret != CKYSUCCESS) {
	goto done;
    }

    /* verify we got the expected response */
    if (!CKYApplet_VerifyResponse(&response, size, apduRC)) {
	ret = CKYAPDUFAIL;
	goto done;
    }

    /* Fill in our output data structure */
    ret = (*fillFunc)(&response, size, fillArg);
done:
    CKYBuffer_FreeData(&response);
    CKYAPDU_FreeData(&apdu);
    return ret;
}


/*****************************************************************
 *
 *  The following convience functions convert APDU calls
 *   into function calls, with input and output parameters.
 *   The application is still responsible for 1) creating a connection
 *   to the card, 2) Getting a tranaction long,  then 3) selecting
 *   the appropriate applet (or Card manager). Except for those
 *   calls that have been noted, the appropriate applet is the CoolKey
 *   applet.
 *
 *****************************************************************/
/*
 * Select an applet. Must happen after we start a transaction and before
 * we issue any applet specific command.
 */
CKYStatus
CKYApplet_SelectFile(CKYCardConnection *conn, const CKYBuffer *AID,
							 CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_SelectFile, AID, NULL,
		0, CKYAppletFill_Null, NULL, apduRC);
}

static CKYByte coolkeyid[] = {0x62, 0x76, 0x01, 0xff, 0x00, 0x00, 0x00 };
/*
 * Select the CoolKey applet. Must happen after we start a transaction and 
 * before we issue any applet specific command.
 */
CKYStatus
CKYApplet_SelectCoolKeyManager(CKYCardConnection *conn, CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYBuffer COOLKEYAID;
    CKYBuffer_InitFromData(&COOLKEYAID, coolkeyid, sizeof(coolkeyid));
    ret = CKYApplet_HandleAPDU(conn, CKYAppletFactory_SelectFile, &COOLKEYAID,
		 NULL, 0, CKYAppletFill_Null, NULL, apduRC);
    CKYBuffer_FreeData(&COOLKEYAID);
    return ret;
}

static CKYByte CACPKIid[] = {0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00 };
/*
 * Select the CoolKey applet. Must happen after we start a transaction and 
 * before we issue any applet specific command.
 */
CKYStatus
CACApplet_SelectPKI(CKYCardConnection *conn, CKYByte instance, 
			       CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYBuffer CACPKIAID;
    CKYBuffer_InitFromData(&CACPKIAID, CACPKIid, sizeof(CACPKIid));
    CKYBuffer_SetChar(&CACPKIAID, 6, instance);
    ret = CKYApplet_HandleAPDU(conn, CKYAppletFactory_SelectFile, &CACPKIAID,
		 NULL, CKY_SIZE_UNKNOWN, CKYAppletFill_Null, NULL, apduRC);
    CKYBuffer_FreeData(&CACPKIAID);
    return ret;
}

/*
 * Select the card manager. Must happen after we start a transaction and before
 * we issue any card manager commands.
 */
CKYStatus
CKYApplet_SelectCardManager(CKYCardConnection *conn, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_SelectCardManager, NULL,
		NULL, 0, CKYAppletFill_Null, NULL, apduRC);
}

static CKYByte cacmgrid[] = {0xa0, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 };
CKYStatus
CACApplet_SelectCardManager(CKYCardConnection *conn, CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYBuffer CAC_CM_AID;
    CKYBuffer_InitFromData(&CAC_CM_AID, cacmgrid, sizeof(cacmgrid));
    ret = CKYApplet_HandleAPDU(conn, CKYAppletFactory_SelectFile, &CAC_CM_AID,
		 NULL, 0, CKYAppletFill_Null, NULL, apduRC);
    CKYBuffer_FreeData(&CAC_CM_AID);
    return ret;
}

/*
 * GetCPLC cluster -- must be called with CM selected
 */
static CKYStatus
ckyAppletFill_GetCPLCData(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespGetCPLCData *gcdp = (CKYAppletRespGetCPLCData *)param;

    gcdp->CPLCtag = CKYBuffer_GetShort(response, 0);
    gcdp->length = CKYBuffer_GetChar(response, 2);
    gcdp->fabricator = CKYBuffer_GetShort(response, 3);
    gcdp->romType = CKYBuffer_GetShort(response, 5);
    gcdp->romOSID = CKYBuffer_GetShort(response, 7);
    gcdp->romOSDate = CKYBuffer_GetShort(response, 9);
    gcdp->romOSLevel = CKYBuffer_GetShort(response, 11);
    gcdp->eepromFabricationDate = CKYBuffer_GetShort(response, 13);
    gcdp->eepromSerialNumber = CKYBuffer_GetLong(response, 15);
    gcdp->eepromBatchID = CKYBuffer_GetShort(response, 19);
    gcdp->eepromModuleFabricator = CKYBuffer_GetShort(response, 21);
    gcdp->eepromModuleDate = CKYBuffer_GetShort(response, 23);
    gcdp->eepromICManufacturer = CKYBuffer_GetShort(response, 25);
    gcdp->eepromEmbeddingDate = CKYBuffer_GetShort(response, 27);
    gcdp->eepromPrePersonalizer = CKYBuffer_GetShort(response, 29);
    gcdp->eepromPrePersonalizeDate = CKYBuffer_GetShort(response, 31);
    gcdp->eepromPrePersonalizeID = CKYBuffer_GetLong(response, 33);
    gcdp->eepromPersonalizer = CKYBuffer_GetShort(response, 37);
    gcdp->eepromPersonalizeDate = CKYBuffer_GetShort(response, 39);
    gcdp->eepromPersonalizeID = CKYBuffer_GetLong(response, 41);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetCPLCData(CKYCardConnection *conn, CKYAppletRespGetCPLCData *cplc,
							CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetCPLCData, NULL, NULL,
		CKY_SIZE_GET_CPLCDATA, ckyAppletFill_GetCPLCData, cplc, apduRC);
}

/*
 * Get CUID. The CUID exists in the CPLC data. We use the same basic
 * APDU, but use a differ fill function to collect it.
 */
static CKYStatus
ckyAppletFill_GetCUID(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYBuffer *cuid = (CKYBuffer *)param;
    CKYStatus ret;

    ret = CKYBuffer_Resize(cuid,10);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    /* fabricator 2 bytes */
    CKYBuffer_SetChar(cuid, 0, CKYBuffer_GetChar(response, 3));
    CKYBuffer_SetChar(cuid, 1, CKYBuffer_GetChar(response, 4));
    /* IC Type 2 bytes */
    CKYBuffer_SetChar(cuid, 2, CKYBuffer_GetChar(response, 5));
    CKYBuffer_SetChar(cuid, 3, CKYBuffer_GetChar(response, 6));
    /* Batch ID 2 bytes */
    CKYBuffer_SetChar(cuid, 4, CKYBuffer_GetChar(response, 19));
    CKYBuffer_SetChar(cuid, 5, CKYBuffer_GetChar(response, 20));
    /* IC Serial Number 4 bytes */
    CKYBuffer_SetChar(cuid, 6, CKYBuffer_GetChar(response, 15));
    CKYBuffer_SetChar(cuid, 7, CKYBuffer_GetChar(response, 16));
    CKYBuffer_SetChar(cuid, 8, CKYBuffer_GetChar(response, 17));
    CKYBuffer_SetChar(cuid, 9, CKYBuffer_GetChar(response, 18));
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetCUID(CKYCardConnection *conn, CKYBuffer *cuid, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetCPLCData, NULL, NULL,
		CKY_SIZE_GET_CPLCDATA, ckyAppletFill_GetCUID, cuid, apduRC);
}

/*
 * Get MSN. The MSN exists in the CPLC data. We use the same basic
 * APDU, but use a differ fill function to collect it.
 */
static CKYStatus
ckyAppletFill_GetMSN(const CKYBuffer *response, CKYSize size, void *param)
{
    unsigned long *msn = (unsigned long *)param;
    *msn = CKYBuffer_GetLong(response, 41);

    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetMSN(CKYCardConnection *conn, unsigned long *msn,
							 CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetCPLCData, NULL, NULL,
		CKY_SIZE_GET_CPLCDATA, ckyAppletFill_GetMSN, msn, apduRC);
}

/*
 * ListKeys cluster
 */
static CKYStatus
ckyAppletFill_ListKeys(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespListKeys *lkp = (CKYAppletRespListKeys *)param;

    lkp->keyNum = CKYBuffer_GetChar(response, 0);
    lkp->keyType = CKYBuffer_GetChar(response, 1);
    lkp->keyPartner = CKYBuffer_GetChar(response, 2);
    lkp->keySize = CKYBuffer_GetShort(response, 3);
    lkp->readACL = CKYBuffer_GetShort(response, 5);
    lkp->writeACL = CKYBuffer_GetShort(response, 7);
    lkp->useACL = CKYBuffer_GetShort(response, 9);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_ListKeys(CKYCardConnection *conn, CKYByte seq,
		CKYAppletRespListKeys *lkp, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ListKeys, &seq, NULL,
	CKY_SIZE_LIST_KEYS, ckyAppletFill_ListKeys, lkp, apduRC);
}

/*
 * Compute Crypt Cluster.
 *
 * Compute Crypt takes 3 types: Init, Process, Final.
 *
 */
CKYStatus
CKYApplet_ComputeCryptInit(CKYCardConnection *conn, CKYByte keyNumber,
	CKYByte mode, CKYByte direction, CKYByte location,
				const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgComputeCrypt ccd;
    ccd.keyNumber = keyNumber;
    ccd.mode = mode;
    ccd.direction = direction;
    ccd.location = location;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ComputeCryptInit, &ccd,
	nonce, 0, CKYAppletFill_Null, NULL, apduRC);
}

CKYStatus
CKYApplet_ComputeCryptProcess(CKYCardConnection *conn, CKYByte keyNumber,
	CKYByte location, const CKYBuffer *data,
				const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgComputeCrypt ccd;
    ccd.keyNumber = keyNumber;
    ccd.location = location;
    ccd.data = data;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ComputeCryptProcess, &ccd,
	nonce, 0, CKYAppletFill_Null, NULL, apduRC);
}

/* computeCrypt returns data in the form :
 * 		len: short
 * 		data: byte[len]
 * This fill routine returns A buffer with a copy of data and a length of len */
static CKYStatus
ckyAppletFill_ComputeCryptFinal(const CKYBuffer *response,
						CKYSize size, void *param)
{
    CKYBuffer *cbuf = (CKYBuffer *)param;
    CKYSize respSize = CKYBuffer_Size(response);
    CKYSize dataLen;

    if (cbuf == 0) {
	return CKYSUCCESS; /* app didn't want the result */
    }
    /* data response code + length code */
    if (respSize < 4) {
	return CKYAPDUFAIL;
    }
    dataLen = CKYBuffer_GetShort(response, 0);
    if (dataLen > (respSize-4)) {
	return CKYAPDUFAIL;
    }
    return CKYBuffer_Replace(cbuf, 0, CKYBuffer_Data(response)+2, dataLen);
}

CKYStatus
CKYApplet_ComputeCryptFinal(CKYCardConnection *conn, CKYByte keyNumber,
    CKYByte location, const CKYBuffer *data, CKYBuffer *sig, CKYBuffer *result,
				const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgComputeCrypt ccd;
    ccd.keyNumber = keyNumber;
    ccd.location = location;
    ccd.data = data;
    ccd.data = sig;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ComputeCryptFinal, &ccd,
	nonce, CKY_SIZE_UNKNOWN, ckyAppletFill_ComputeCryptFinal, result, apduRC);
}

/*
 * do a complete ComputeCrypt operation
 *  ...look to data size to see if we should read/write the data to
 *  the on card buffer. (future)
 */
CKYStatus
CKYApplet_ComputeCrypt(CKYCardConnection *conn, CKYByte keyNumber,
    CKYByte mode, CKYByte direction, const CKYBuffer *data, CKYBuffer *sig,
	 	CKYBuffer *result, const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYAppletArgComputeCrypt ccd;
    CKYBuffer    empty;
    CKYISOStatus status;
    int         use2APDUs = 0;

    CKYBuffer_InitEmpty(&empty);
    ccd.keyNumber = keyNumber;
    ccd.mode      = mode;
    ccd.direction = direction;
    ccd.location  = CKY_DL_APDU;

    if (!apduRC)
    	apduRC = &status;

    if (mode == CKY_RSA_NO_PAD) {
	ccd.data = data;
	ccd.sig  = sig;
	ret = CKYApplet_HandleAPDU(conn, 
			    CKYAppletFactory_ComputeCryptOneStep, &ccd, nonce, 
			    CKY_SIZE_UNKNOWN, ckyAppletFill_ComputeCryptFinal, 
			    result, apduRC);
    	if (ret == CKYAPDUFAIL && *apduRC == CKYISO_INCORRECT_P2) {
	    use2APDUs = 1;  /* maybe it's an old applet */
	}
    } else {
    	use2APDUs = 1;
    }
    if (use2APDUs) {
	/* future, if data is to big write it to the internal object
	 * and set location to DL_OBJECT */
	ccd.data = &empty;
	ccd.sig = sig;

	ret = CKYApplet_HandleAPDU(conn, 
			    CKYAppletFactory_ComputeCryptInit, &ccd, nonce, 
			    0, CKYAppletFill_Null, NULL, apduRC);
	if (ret == CKYSUCCESS) {
	    ccd.data = data;
	    ret = CKYApplet_HandleAPDU(conn, 
			    CKYAppletFactory_ComputeCryptFinal, &ccd, nonce, 
			    CKY_SIZE_UNKNOWN, ckyAppletFill_ComputeCryptFinal, 
			    result, apduRC);
	}
    }
    return ret;
}

/*
 * do a CAC Sign/Decrypt
 */
CKYStatus
CACApplet_SignDecrypt(CKYCardConnection *conn, const CKYBuffer *data, 
	 	CKYBuffer *result, CKYISOStatus *apduRC)
{
    CKYStatus ret;

    ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_SignDecrypt, data, NULL, 
			    CKYBuffer_Size(data), CKYAppletFill_ReplaceBuffer, 
			    result, apduRC);
    return ret;
}

/*
 * do a CAC VerifyPIN
 */
CKYStatus
CACApplet_VerifyPIN(CKYCardConnection *conn, const char *pin, 
		    CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYISOStatus status;
    if (apduRC == NULL) {
	apduRC = &status;
    }

    ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_VerifyPIN, pin, NULL, 
			    0, CKYAppletFill_Null, 
			    NULL, apduRC);
    /* it's unfortunate that the same code that means 'more data to follow' for
     * GetCertificate also means, auth failure, you only have N more attempts
     * left in the verify PIN call */
    if ((*apduRC & CKYISO_MORE_MASK) == CKYISO_MORE) {
	ret = CKYAPDUFAIL;
    }
    return ret;
}

/*
 * Get a CAC Certificate 
 */
CKYStatus
CACApplet_GetCertificate(CKYCardConnection *conn, CKYBuffer *cert, 
		    CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYISOStatus status;
    CKYSize size = 100;

    CKYBuffer_Resize(cert,0);
    if (apduRC == NULL) {
	apduRC = &status;
    }

    ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_GetCertificate, &size, NULL, 
			    CKY_SIZE_UNKNOWN, CKYAppletFill_AppendBuffer, cert,
			    apduRC);
    while ((*apduRC & CKYISO_MORE_MASK) == CKYISO_MORE) {
	size = *apduRC & ~CKYISO_MORE_MASK;
    	ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_GetCertificate, &size, NULL, 
			    CKY_SIZE_UNKNOWN, CKYAppletFill_AppendBuffer, cert,
			    apduRC);
    }
    return ret;
}
CKYStatus 
CACApplet_GetCertificateFirst(CKYCardConnection *conn, CKYBuffer *cert, 
			CKYSize *nextSize, CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYISOStatus status;
    CKYSize size = 100;

    CKYBuffer_Resize(cert,0);
    if (apduRC == NULL) {
	apduRC = &status;
    }
    *nextSize = 0;

    ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_GetCertificate, &size, NULL, 
			    CKY_SIZE_UNKNOWN, CKYAppletFill_AppendBuffer, cert,
			    apduRC);
    if ((*apduRC & CKYISO_MORE_MASK) == CKYISO_MORE) {
	*nextSize = *apduRC & ~CKYISO_MORE_MASK;
    }
    return ret;
}

CKYStatus 
CACApplet_GetCertificateAppend(CKYCardConnection *conn, CKYBuffer *cert, 
			CKYSize nextSize, CKYISOStatus *apduRC)
{
    CKYStatus ret;
    CKYISOStatus status;
    CKYSize size = nextSize;

    if (apduRC == NULL) {
	apduRC = &status;
    }

    ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_GetCertificate, &size, NULL, 
			    CKY_SIZE_UNKNOWN, CKYAppletFill_AppendBuffer, cert,
			    apduRC);
    while ((*apduRC & CKYISO_MORE_MASK) == CKYISO_MORE) {
	size = *apduRC & ~CKYISO_MORE_MASK;
    	ret = CKYApplet_HandleAPDU(conn, 
			    CACAppletFactory_GetCertificate, &size, NULL, 
			    CKY_SIZE_UNKNOWN, CKYAppletFill_AppendBuffer, cert,
			    apduRC);
    }
    return ret;
}


/*
 * PIN cluster
 */
CKYStatus
CKYApplet_CreatePIN(CKYCardConnection *conn, CKYByte pinNumber,
   			CKYByte maxAttempts, const char *pinValue,
			const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgCreatePIN cpd;
    cpd.pinValue = pinValue;
    cpd.maxAttempts = maxAttempts;
    cpd.pinValue = pinValue;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_CreatePIN, &cpd, nonce,
	0, CKYAppletFill_Null, NULL, apduRC);

}

CKYStatus
CKYApplet_VerifyPIN(CKYCardConnection *conn, CKYByte pinNumber,
		const char *pinValue, CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgVerifyPIN vpd;
    vpd.pinValue = pinValue;
    vpd.pinNumber = pinNumber;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_VerifyPIN, &vpd, NULL,
	8, CKYAppletFill_ReplaceBuffer, nonce, apduRC);
}

CKYStatus
CKYApplet_ChangePIN(CKYCardConnection *conn, const char *oldPin,
    	const char *newPin, const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgChangePIN cpd;
    cpd.oldPin = oldPin;
    cpd.newPin = newPin;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ChangePIN, &cpd, nonce,
	0, CKYAppletFill_Null, NULL, apduRC);
}

CKYStatus
CKYApplet_ListPINs(CKYCardConnection *conn,  unsigned short *pins,
						CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ListPINs, NULL, NULL,
	CKY_SIZE_LIST_PINS, CKYAppletFill_Short, pins, apduRC);
}

CKYStatus
CKYApplet_Logout(CKYCardConnection *conn, CKYByte pinNumber,
				const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_Logout, &pinNumber, nonce,
	0, CKYAppletFill_Null, NULL, apduRC);
}

CKYStatus
CKYApplet_CreateObject(CKYCardConnection *conn, unsigned long objectID,
	CKYSize size, unsigned short readACL, unsigned short writeACL,
	unsigned short deleteACL, const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgCreateObject cod;
    cod.objectID = objectID;
    cod.size = size;
    cod.readACL = readACL;
    cod.writeACL = writeACL;
    cod.deleteACL = deleteACL;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_CreateObject, &cod, 
	nonce, 0, CKYAppletFill_Null, NULL, apduRC);
}

CKYStatus
CKYApplet_DeleteObject(CKYCardConnection *conn, unsigned long objectID,
	CKYByte zero, const CKYBuffer *nonce, CKYISOStatus *apduRC)
{
    CKYAppletArgDeleteObject dod;
    dod.objectID = objectID;
    dod.zero = zero;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_DeleteObject, &dod, 
	nonce, 0, CKYAppletFill_Null, NULL, apduRC);
}

/*
 * Read Object cluster...
 *   This is the raw version that goes issues a single APDU.
 */
CKYStatus
CKYApplet_ReadObject(CKYCardConnection *conn, unsigned long objectID,
		CKYOffset offset, CKYByte size, const CKYBuffer *nonce,
		CKYBuffer *data, CKYISOStatus *apduRC)
{
    CKYAppletArgReadObject rod;

    rod.objectID = objectID;
    rod.offset = offset;
    rod.size = size;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ReadObject, &rod, nonce,
	size, CKYAppletFill_ReplaceBuffer, data, apduRC);
}

/*
 * Read Object Append cluster...
 *   This is also issues a single APDU, but appends the resulting data
 *   to an existing buffer.
 */

CKYStatus
CKYApplet_ReadObjectAppend(CKYCardConnection *conn, unsigned long objectID,
		CKYOffset offset, CKYByte size, const CKYBuffer *nonce,
		CKYBuffer *data, CKYISOStatus *apduRC)
{
    CKYAppletArgReadObject rod;

    rod.objectID = objectID;
    rod.offset = offset;
    rod.size = size;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ReadObject, &rod, nonce,
	size, CKYAppletFill_AppendBuffer, data, apduRC);
}

/*
 * Read Object
 *   This is makes multiple APDU calls to read the entire object.
 */
CKYStatus
CKYApplet_ReadObjectFull(CKYCardConnection *conn, unsigned long objectID,
		CKYOffset offset, CKYSize size, const CKYBuffer *nonce,
		CKYBuffer *data, CKYISOStatus *apduRC)
{
    CKYAppletArgReadObject rod;
    CKYStatus ret = CKYSUCCESS;

    rod.objectID = objectID;
    rod.offset = offset;
    do {
	rod.size = (CKYByte) MIN(size, CKY_MAX_READ_CHUNK_SIZE);
	ret = CKYApplet_HandleAPDU(conn, CKYAppletFactory_ReadObject, &rod,
	   nonce, rod.size, CKYAppletFill_AppendBuffer, data, apduRC);
	size -= rod.size;
	rod.offset += rod.size;
    } while ((size > 0) && (ret == CKYSUCCESS));

    return ret;
}

/*
 * List Object cluster
 */
static CKYStatus
ckyAppletFill_ListObjects(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespListObjects *lop = (CKYAppletRespListObjects *)param;

    lop->objectID = CKYBuffer_GetLong(response, 0);
    lop->objectSize = CKYBuffer_GetLong(response, 4);
    lop->readACL = CKYBuffer_GetShort(response, 8);
    lop->writeACL = CKYBuffer_GetShort(response, 10);
    lop->deleteACL = CKYBuffer_GetShort(response, 12);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_ListObjects(CKYCardConnection *conn, CKYByte seq,
		CKYAppletRespListObjects *lop, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_ListObjects, &seq, NULL,
	CKY_SIZE_LIST_OBJECTS, ckyAppletFill_ListObjects, lop, apduRC);
}

/*
 * GetStatus cluster
 */
static CKYStatus
ckyAppletFill_GetStatus(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespGetStatus *gsp = (CKYAppletRespGetStatus *)param;

    gsp->protocolMajorVersion = CKYBuffer_GetChar(response, 0);
    gsp->protocolMinorVersion = CKYBuffer_GetChar(response, 1);
    gsp->appletMajorVersion = CKYBuffer_GetChar(response, 2);
    gsp->appletMinorVersion = CKYBuffer_GetChar(response, 3);
    gsp->totalObjectMemory = CKYBuffer_GetLong(response, 4);
    gsp->freeObjectMemory = CKYBuffer_GetLong(response, 8);
    gsp->numberPins = CKYBuffer_GetChar(response, 12);
    gsp->numberKeys = CKYBuffer_GetChar(response, 13);
    gsp->loggedInMask = CKYBuffer_GetShort(response, 14);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetStatus(CKYCardConnection *conn, CKYAppletRespGetStatus *status,
							CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetStatus, NULL, NULL,
		CKY_SIZE_GET_STATUS, ckyAppletFill_GetStatus, status, apduRC);
}

CKYStatus
CKYApplet_Noop(CKYCardConnection *conn, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_Noop, NULL, NULL,
		0, CKYAppletFill_Null, NULL, apduRC);
}

CKYStatus
CKYApplet_GetBuildID(CKYCardConnection *conn, unsigned long *buildID,
						CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetBuildID, NULL, NULL,
		CKY_SIZE_GET_BUILDID, CKYAppletFill_Long, buildID, apduRC);
}

/*
 * GetLifeCycle cluster
 */
static CKYStatus
ckyAppletFill_GetLifeCycle(const CKYBuffer *response, CKYSize size, void *param)
{
    *(CKYByte *)param= CKYBuffer_GetChar(response,0);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetLifeCycle(CKYCardConnection *conn, CKYByte *personalized,
							CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetLifeCycle, NULL, NULL,
     CKY_SIZE_GET_LIFE_CYCLE, ckyAppletFill_GetLifeCycle, personalized, apduRC);
}

static CKYStatus
ckyAppletFill_GetLifeCycleV2(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespGetLifeCycleV2 *ext = (CKYAppletRespGetLifeCycleV2 *) param;
    ext->lifeCycle = CKYBuffer_GetChar(response,0);
    ext->pinCount = CKYBuffer_GetChar(response,1);
    ext->protocolMajorVersion = CKYBuffer_GetChar(response,2);
    ext->protocolMinorVersion = CKYBuffer_GetChar(response,3);
    return CKYSUCCESS;
}

/*
 * GetStatus cluster
 */
static CKYStatus
ckyAppletFill_LifeCycleStatus(const CKYBuffer *response, CKYSize size, void *param)
{
    CKYAppletRespGetLifeCycleV2 *ext = (CKYAppletRespGetLifeCycleV2 *) param;
    ext->pinCount = CKYBuffer_GetChar(response,12);
    ext->protocolMajorVersion = CKYBuffer_GetChar(response,0);
    ext->protocolMinorVersion = CKYBuffer_GetChar(response,1);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetLifeCycleV2(CKYCardConnection *conn, 
		CKYAppletRespGetLifeCycleV2 *ext, CKYISOStatus *apduRC)
{
    CKYStatus status;
    status = CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetLifeCycleV2, 
     	NULL,NULL, CKY_SIZE_GET_LIFE_CYCLE_V2, ckyAppletFill_GetLifeCycleV2, 
								ext, apduRC);

     /* Get Life Cycle Version 2 is a new APDU with combines data from
      * two other APDUs. Older tokens don't have this APDU, so use
      * the old method to get the data */
    if (status == CKYAPDUFAIL) {
	status = CKYApplet_GetLifeCycle(conn,&ext->lifeCycle, apduRC);
	if (status != CKYSUCCESS) {
	    return status;
	}
	status = CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetStatus, NULL, 
   	  NULL, CKY_SIZE_GET_STATUS, ckyAppletFill_LifeCycleStatus, ext, apduRC);
    }
    return status;
}

/*
 * GetBuiltin cluster
 */
static CKYStatus
ckyAppletFill_GetBuiltinACL(const CKYBuffer *response,CKYSize size,void *param)
{
    CKYAppletRespGetBuiltinACL *gba = (CKYAppletRespGetBuiltinACL *) param;
    gba->create_object_ACL = CKYBuffer_GetShort(response,0);
    gba->create_object_ACL = CKYBuffer_GetShort(response,2);
    gba->create_object_ACL = CKYBuffer_GetShort(response,4);
    gba->enable_ACL_change = CKYBuffer_GetChar(response,6);
    return CKYSUCCESS;
}

CKYStatus
CKYApplet_GetBuiltinACL(CKYCardConnection *conn, 
		CKYAppletRespGetBuiltinACL *gba, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetBuiltinACL, NULL,
	NULL, CKY_SIZE_GET_BUILTIN_ACL, ckyAppletFill_GetBuiltinACL, gba,
	apduRC);
}

CKYStatus
CKYApplet_GetIssuerInfo(CKYCardConnection *conn, CKYBuffer *info, 
			CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetIssuerInfo, NULL,
     	NULL, CKY_SIZE_GET_ISSUER_INFO, CKYAppletFill_ReplaceBuffer, 
	info, apduRC);
}

CKYStatus
CKYApplet_GetRandom(CKYCardConnection *conn, CKYBuffer *data, CKYByte len,
		    CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetRandom, &len,
     	NULL, len, CKYAppletFill_ReplaceBuffer, data, apduRC);
}

CKYStatus
CKYApplet_GetRandomAppend(CKYCardConnection *conn, CKYBuffer *data, CKYByte len,
		    CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_GetRandom, &len,
     	NULL, len, CKYAppletFill_AppendBuffer, data, apduRC);
}

CKYStatus
CKYApplet_SeedRandom(CKYCardConnection *conn, const CKYBuffer *data,
		    CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_SeedRandom, data,
     	NULL, 0, CKYAppletFill_Null, NULL, apduRC);
}



/*
 * deprecates 0.x functions
 */
/* old applet verify pin call (no nonce returned) */
CKYStatus
CKYApplet_VerifyPinV0(CKYCardConnection *conn, CKYByte pinNumber,
			const char *pinValue, CKYISOStatus *apduRC)
{
    CKYAppletArgVerifyPIN vpd;
    vpd.pinValue = pinValue;
    vpd.pinNumber = pinNumber;

    vpd.pinValue = pinValue;
    vpd.pinNumber = pinNumber;
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_VerifyPIN, &vpd, NULL,
	0, CKYAppletFill_Null, NULL, apduRC);
}

/* logout all */
CKYStatus
CKYApplet_LogoutAllV0(CKYCardConnection *conn, CKYISOStatus *apduRC)
{
    return CKYApplet_HandleAPDU(conn, CKYAppletFactory_LogoutAllV0, NULL, NULL,
	0, CKYAppletFill_Null, NULL, apduRC);
}
