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
 * ***** END COPYRIGHT BLOCK *****/

#include "mypkcs11.h"

#include <assert.h>
#include <string>
#include <map>
#include <set>
#include <memory>
#include "log.h"
#include "PKCS11Exception.h"
#ifdef _WIN32
#include <windows.h>
#endif
#include <winscard.h>
#include "slot.h"
#include "cky_base.h"
#include "params.h"

#define NULL 0

/* static module data --------------------------------  */

static Log *log = NULL;

static SlotList *slotList = NULL;

static OSLock finalizeLock(false);

static CK_BBOOL initialized = FALSE;
static CK_BBOOL finalizing = FALSE;
static CK_BBOOL waitEvent = FALSE;

char *Params::params = NULL;

// manufacturerID and libraryDescription should not be NULL-terminated,
// so the last character is overwritten with a blank in C_GetInfo().
static CK_INFO ckInfo = {
    {2, 11},
    "Mozilla Foundation             ",
    0,
    "CoolKey PKCS #11 Module     ",
    {1, 0}
};

typedef struct {
    CK_MECHANISM_TYPE mech;
    CK_MECHANISM_INFO info;
} MechInfo;

/**********************************************************************
 ************************** MECHANISM TABLE ***************************
 **********************************************************************/
static MechInfo
mechanismList[] = {
    {CKM_RSA_PKCS, { 1024, 4096, CKF_HW | CKF_SIGN | CKF_DECRYPT } }
};
static unsigned int numMechanisms = sizeof(mechanismList)/sizeof(MechInfo);

/* ------------------------------------------------------------ */

void
dumpTemplates(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    // no try here, let caller catch it.  try {
    unsigned long i;
    if (!pTemplate) 
	return;
    for (i = 0; i < ulCount; ++i) {
	CK_ATTRIBUTE_PTR pT = pTemplate + i;
	if (pT->pValue && pT->ulValueLen == 4) {
	    log->log(
	    "template [%02lu] type: %04lx, pValue: %08lx, ulValueLen: %08lx, value: %lu\n", 
	             i, pT->type, pT->pValue, pT->ulValueLen, *(CK_ULONG_PTR)pT->pValue);
	} else 
	    log->log("template [%02lu] type: %04lx, pValue: %08lx, ulValueLen: %08lx\n", 
	             i, pT->type, pT->pValue, pT->ulValueLen);
    }
}

/* PKCS11 defined functions ----------------------------------- */


#define NOTSUPPORTED(name, args) \
CK_RV name args \
{ \
    log->log(#name " called (notSupported)\n"); \
    return CKR_FUNCTION_NOT_SUPPORTED; \
}

#define SUPPORTED(name, name2, dec_args, use_args) \
CK_RV name dec_args \
{ \
    if( ! initialized ) { \
        return CKR_CRYPTOKI_NOT_INITIALIZED; \
    } \
    try { \
	log->log(#name " called\n"); \
	slotList->name2 use_args ; \
	return CKR_OK; \
    } catch(PKCS11Exception& e) { \
        e.log(log); \
        return e.getCRV(); \
    } \
}



extern "C" {

NOTSUPPORTED(C_InitToken,(CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR))
NOTSUPPORTED(C_InitPIN,  (CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG))
NOTSUPPORTED(C_SetPIN,   (CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG))
NOTSUPPORTED(C_GetOperationState, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR))
NOTSUPPORTED(C_SetOperationState, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE))
NOTSUPPORTED(C_CreateObject, (CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_CopyObject, (CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_DestroyObject, (CK_SESSION_HANDLE, CK_OBJECT_HANDLE))
NOTSUPPORTED(C_GetObjectSize, (CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ULONG_PTR))
NOTSUPPORTED(C_SetAttributeValue, (CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG))
NOTSUPPORTED(C_EncryptInit, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))
NOTSUPPORTED(C_Encrypt, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))
NOTSUPPORTED(C_EncryptUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_EncryptFinal, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DecryptUpdate,(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DecryptFinal, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DigestInit, (CK_SESSION_HANDLE,CK_MECHANISM_PTR))
NOTSUPPORTED(C_Digest, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DigestUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG))
NOTSUPPORTED(C_DigestKey, (CK_SESSION_HANDLE,CK_OBJECT_HANDLE))
NOTSUPPORTED(C_DigestFinal, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR))
NOTSUPPORTED(C_SignUpdate, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG))
NOTSUPPORTED(C_SignFinal, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_SignRecoverInit, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))
NOTSUPPORTED(C_SignRecover, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_VerifyInit, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))
NOTSUPPORTED(C_Verify, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG))
NOTSUPPORTED(C_VerifyUpdate, (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG))
NOTSUPPORTED(C_VerifyFinal, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG))
NOTSUPPORTED(C_VerifyRecoverInit, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))
NOTSUPPORTED(C_VerifyRecover, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DigestEncryptUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DecryptDigestUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_SignEncryptUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_DecryptVerifyUpdate, (CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_GenerateKey, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_GenerateKeyPair, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_WrapKey, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))
NOTSUPPORTED(C_UnwrapKey, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_DeriveKey, (CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))
NOTSUPPORTED(C_GetFunctionStatus, (CK_SESSION_HANDLE))
NOTSUPPORTED(C_CancelFunction, (CK_SESSION_HANDLE))

/* non-specialized functions supported with the slotList object */

SUPPORTED(C_GetSlotList, getSlotList,
  (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount),
  (tokenPresent, pSlotList, pulCount))
SUPPORTED(C_GetSessionInfo, getSessionInfo,
   (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo),
   (hSession, pInfo) )
SUPPORTED(C_Logout, logout, (CK_SESSION_HANDLE hSession), (hSession))
SUPPORTED(C_Decrypt, decrypt, 
   (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen),
   (hSession, pData, ulDataLen, pDecryptedData, pulDecryptedDataLen))
SUPPORTED(C_DecryptInit, decryptInit,
   (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, 
    CK_OBJECT_HANDLE hKey), (hSession, pMechanism, hKey))
SUPPORTED(C_SignInit, signInit, 
   (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, 
    CK_OBJECT_HANDLE hKey), 
   (hSession, pMechanism, hKey))
SUPPORTED(C_Sign, sign, 
   (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, 
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen), 
  (hSession, pData, ulDataLen, pSignature, pulSignatureLen))
SUPPORTED(C_SeedRandom, seedRandom,
  (CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen),
  (hSession, data, dataLen))
SUPPORTED(C_GenerateRandom, generateRandom,
  (CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen),
  (hSession, data, dataLen))

/* non-specialized functions supported with the slot directly */

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
  try {
    if( initialized ) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    if (!finalizeLock.isValid()) {
	return CKR_CANT_LOCK;
    }
    CK_C_INITIALIZE_ARGS* initArgs = (CK_C_INITIALIZE_ARGS*) pInitArgs;
    if( initArgs != NULL ) {
	/* work around a bug in NSS where the library parameters are only
	 * send if locking is requested */
	if (initArgs->LibraryParameters) {
	    Params::SetParams(strdup((char *)initArgs->LibraryParameters));
	} else {
	    Params::ClearParams();
	}
        if( (initArgs->flags & CKF_OS_LOCKING_OK) || initArgs->LockMutex ){
            throw PKCS11Exception(CKR_CANT_LOCK);
        }
    }
    char * logFileName = getenv("COOL_KEY_LOG_FILE");
    if (logFileName) {
	if (strcmp(logFileName,"SYSLOG") == 0) {
	    log = new SysLog();
	} else {
	    log = new FileLog(logFileName);
	}
    } else {
	log = new DummyLog();
    }
    log->log("Initialize called, hello %d\n", 5);
    CKY_SetName("coolkey");
    slotList = new SlotList(log);
    initialized = TRUE;
    return CKR_OK;
  } catch(PKCS11Exception &e) {
        if( log )
            e.log(log);
        return e.getReturnValue();
  }
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // XXX cleanup all data structures !!!
    //delete sessionManager;
    log->log("Finalizing...\n");
    // don't race the setting of finalizing. If C_WaitEvent gets passed
    // the finalizing call first, we know it will set waitEvent before
    // we can get the lock, so we only need to protect setting finalizing
    // to true.
    finalizeLock.getLock();
    finalizing = TRUE;
    finalizeLock.releaseLock();
    if (waitEvent) {
	/* we're waiting on a slot event, shutdown first to allow
	 * the wait function to complete before we pull the rug out.
	 */
	slotList->shutdown();
	while (waitEvent) {
	    OSSleep(500);
	}
    } 
    delete slotList;
    delete log;
    finalizeLock.getLock();
    finalizing = FALSE;
    initialized = FALSE;
    finalizeLock.releaseLock();
    return CKR_OK;
}


CK_RV
C_GetInfo(CK_INFO_PTR p)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    log->log("C_GetInfo called\n");
    ckInfo.manufacturerID[31] = ' ';
    ckInfo.libraryDescription[31] = ' ';
    *p = ckInfo;
    return CKR_OK;
}


CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pSlotInfo)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("Called C_GetSlotInfo\n");
        slotList->validateSlotID(slotID);
        return slotList->getSlot(
            slotIDToIndex(slotID))->getSlotInfo(pSlotInfo);
    } catch( PKCS11Exception &excep ) {
        excep.log(log);
        return excep.getCRV();
    }
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pTokenInfo)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_GetTokenInfo called\n");
        slotList->validateSlotID(slotID);
        return slotList->getSlot(
            slotIDToIndex(slotID))->getTokenInfo(pTokenInfo);
    } catch( PKCS11Exception &excep ) {
        excep.log(log);
        return excep.getCRV();
    }
}

CK_RV
C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        CK_RV rv = CKR_OK;

        log->log("C_GetMechanismList called\n");
        if( pulCount == NULL ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }

        slotList->validateSlotID(slotID);
        if( ! slotList->getSlot(
            slotIDToIndex(slotID))->isTokenPresent() ) {
            return CKR_TOKEN_NOT_PRESENT;
        }

        if( pMechanismList != NULL ) {
            if( *pulCount < numMechanisms ) {
                rv = CKR_BUFFER_TOO_SMALL;
            } else {
                for(unsigned int i=0; i < numMechanisms; ++i ) {
                    pMechanismList[i] = mechanismList[i].mech;
                }
            }
        }

        *pulCount = numMechanisms;
            
        log->log("C_GetMechanismList returning %d\n", rv);
        return rv;

    } catch(PKCS11Exception &excep ) {
        excep.log(log);
        return excep.getCRV();
    }

}

CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_GetMechanismInfo called\n");
        if( pInfo == NULL ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        slotList->validateSlotID(slotID);
        if( ! slotList->getSlot(slotIDToIndex(slotID))->isTokenPresent() ) {
            return CKR_TOKEN_NOT_PRESENT;
        }

        for(unsigned int i=0; i < numMechanisms; ++i ) {
            if( mechanismList[i].mech == type ) {
                *pInfo = mechanismList[i].info;
                log->log("C_GetMechanismInfo got info about %d\n", type);
                return CKR_OK;
            }
        }
        log->log("C_GetMechanismInfo failed to find info about %d\n", type);
        return CKR_MECHANISM_INVALID; // mechanism not in the list
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_OpenSession called\n");
        slotList->validateSlotID(slotID);
#ifdef LATER  // the CSP isn't setting this bit right now.
        if( ! (flags & CKF_SERIAL_SESSION) ) {
            throw PKCS11Exception(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
#endif
        if( phSession == NULL ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        Session::Type sessionType =
            (flags & CKF_RW_SESSION) ? Session::RW : Session::RO;

        slotList->openSession(sessionType, slotID, phSession);

        return CKR_OK;

    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_CloseSession(0x%x) called\n", hSession);
        // !!!XXX Hack
        // If nothing else, we need to logout the token when all
        // its sessions are closed.
        return CKR_OK;
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}

CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_CloseAllSessions(0x%x) called\n", slotID);
        slotList->validateSlotID(slotID);
        // !!!XXX Hack
        // If nothing else, we need to logout the token when all
        // its sessions are closed.
        return CKR_OK;
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}


CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_FindObjectsInit called, %lu templates\n", ulCount);
	dumpTemplates(pTemplate, ulCount);

        if( pTemplate == NULL && ulCount != 0 ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        slotList->findObjectsInit(hSession, pTemplate, ulCount);
        return CKR_OK;
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    CK_ULONG count = 0;
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_FindObjects called, max objects = %lu\n", ulMaxObjectCount );
        if( phObject == NULL && ulMaxObjectCount != 0 ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        slotList->findObjects(hSession, phObject, ulMaxObjectCount,
            pulObjectCount);
	count = *pulObjectCount;
        log->log("returned %lu objects:", count );
	CK_ULONG i;
	for (i = 0; i < count; ++i) {
	    log->log(" 0x%08lx", phObject[i]);
	}
        log->log("\n" );
        return CKR_OK;
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // we don't need to do any cleaup. We could check the session handle.
    return CKR_OK;
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_Login called\n");
        if( userType != CKU_USER ) {
            throw PKCS11Exception(CKR_USER_TYPE_INVALID);
        }
        if( pPin == NULL ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        slotList->login(hSession, pPin, ulPinLen);
        return CKR_OK;
    } catch(PKCS11Exception &e) {
        e.log(log);
        return e.getCRV();
    }
}


CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    try {
        log->log("C_GetAttributeValue called, %lu templates for object 0x%08lx\n", ulCount, hObject);
	dumpTemplates(pTemplate, ulCount);
        if( pTemplate == NULL && ulCount != 0 ) {
            throw PKCS11Exception(CKR_ARGUMENTS_BAD);
        }
        slotList->getAttributeValue(hSession, hObject, pTemplate, ulCount);
	dumpTemplates(pTemplate, ulCount);
        return CKR_OK;
    } catch(PKCS11Exception& e) {
	CK_RV rv = e.getCRV();
        e.log(log);
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID ||
	    rv == CKR_BUFFER_TOO_SMALL) {
	    dumpTemplates(pTemplate, ulCount);
	}
        return rv;
    }
}


/*
 * While the rest of the C_ calls are protected by the callers lock,
 * C_WaitForSlotEvent is guaranteed to be on a separate thread.
 * Make sure we are locking with C_Finalize, which is likely to be racing
 * with this function
 */
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    finalizeLock.getLock();
    if( ! initialized ) {
        finalizeLock.releaseLock();
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (finalizing) {
        finalizeLock.releaseLock();
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    waitEvent = TRUE;
    finalizeLock.releaseLock();
    try {
        log->log("C_WaitForSlotEvent called\n");
        slotList->waitForSlotEvent(flags, pSlot, pReserved);
        waitEvent = FALSE;
        return CKR_OK;
    } catch(PKCS11Exception& e) {
        e.log(log);
        waitEvent = FALSE;
        return e.getCRV();
    }
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr);


#undef  CK_NEED_ARG_LIST
#undef  CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(func) (CK_##func) func,

static CK_FUNCTION_LIST
functionList =  {
    {2, 20}, // PKCS #11 spec version we support
#include "pkcs11f.h"
};

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr)
{
    if( pPtr == NULL ) {
        return CKR_ARGUMENTS_BAD;
    }
    *pPtr = &functionList;
    return CKR_OK;
}


} // end extern C

