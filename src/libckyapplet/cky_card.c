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

#include <winscard.h>
#include <stdlib.h>
#include <string.h>
#include "cky_basei.h" /* friend class */
#include "cky_base.h"
#include "cky_card.h"
#include "dynlink.h"

#ifndef WINAPI
#define WINAPI
typedef SCARD_READERSTATE *LPSCARD_READERSTATE;
#endif

#ifndef SCARD_E_NO_READERS_AVAILABLE
#define SCARD_E_NO_READERS_AVAILABLE ((unsigned long)0x8010002EL)
#endif

#define NEW(type,count) (type *)malloc((count)*sizeof(type))

/*
 * protect against scard API not being installed.
 */

typedef long (WINAPI * SCardEstablishContextFn) (
    unsigned long dwScope,
    const void * pvReserved1,
    const void * pvReserved2,
    LPSCARDCONTEXT phContext);

typedef long (WINAPI * SCardReleaseContextFn) (
    SCARDCONTEXT hContext);

typedef long (WINAPI * SCardBeginTransactionFn) (
    long hCard);

typedef long (WINAPI * SCardEndTransactionFn) (
    long hCard,
    unsigned long dwDisposition);

typedef long (WINAPI * SCardConnectFn) (
    SCARDCONTEXT hContext,
    const char *szReader,
    unsigned long dwShareMode,
    unsigned long dwPreferredProtocols,
    long *phCard,
    unsigned long *pdwActiveProtocol);

typedef long (WINAPI * SCardDisconnectFn) (
    long hCard,
    unsigned long dwDisposition);

typedef long (WINAPI * SCardTransmitFn) (
    long hCard,
    LPCSCARD_IO_REQUEST pioSendPci,
    const unsigned char *pbSendBuffer,
    unsigned long cbSendLength,
    LPSCARD_IO_REQUEST pioRecvPci,
    unsigned char *pbRecvBuffer,
    unsigned long *pcbRecvLength);

typedef long (WINAPI * SCardReconnectFn) (
    long hCard,
    unsigned long dwShareMode,
    unsigned long dwPreferredProtocols,
    unsigned long dwInitialization,
    unsigned long *pdwActiveProtocol);

typedef long (WINAPI * SCardListReadersFn) (
    SCARDCONTEXT hContext,
    const char *mszGroups,
    char *mszReaders,
    unsigned long *pcchReaders);

typedef long (WINAPI * SCardStatusFn) (
    long hCard,
    char *mszReaderNames,
    unsigned long *pcchReaderLen,
    unsigned long *pdwState,
    unsigned long *pdwProtocol,
    unsigned char *pbAtr,
    unsigned long *pcbAtrLen);

typedef long (WINAPI * SCardGetAttribFn) (
    long hCard,
    unsigned long dwAttId,
    char *pbAttr,
    unsigned long *pchAttrLen);

typedef long (WINAPI * SCardGetStatusChangeFn) (
    SCARDCONTEXT hContext,
    unsigned long dwTimeout,
    LPSCARD_READERSTATE rgReaderStates,
    unsigned long cReaders);

typedef long (WINAPI * SCardCancelFn) (
    SCARDCONTEXT hContext);

typedef struct _SCard {
    SCardEstablishContextFn SCardEstablishContext;
    SCardReleaseContextFn SCardReleaseContext;
    SCardBeginTransactionFn SCardBeginTransaction;
    SCardEndTransactionFn SCardEndTransaction;
    SCardConnectFn SCardConnect;
    SCardDisconnectFn SCardDisconnect;
    SCardTransmitFn SCardTransmit;
    SCardReconnectFn SCardReconnect;
    SCardListReadersFn SCardListReaders;
    SCardStatusFn SCardStatus;
    SCardGetAttribFn SCardGetAttrib;
    SCardGetStatusChangeFn SCardGetStatusChange;
    SCardCancelFn SCardCancel;
    SCARD_IO_REQUEST *SCARD_PCI_T0_;
} SCard;

#define GET_ADDRESS(library, scard, name) \
    status= ckyShLibrary_getAddress(library,  \
			(void**) &scard->name, MAKE_DLL_SYMBOL(name)); \
    if (status != CKYSUCCESS) { \
        goto fail; \
    }

#ifdef WIN32
#define SCARD_LIB_NAME "winscard.dll"
#else
#ifdef MAC
#define SCARD_LIB_NAME "PCSC.Framework/PCSC"
#else
#ifdef LINUX
#define SCARD_LIB_NAME "libpcsclite.so"
#else
#ifndef SCARD_LIB_NAME
#error "define wincard library for this platform"
#endif
#endif
#endif
#endif

static SCard *
ckySCard_Init(void)
{
    ckyShLibrary library;
    CKYStatus status;
    SCard *scard = NEW(SCard, 1);

    if (!scard) {
	return NULL;
    }

    library = ckyShLibrary_open(SCARD_LIB_NAME);
    if (!library) {
	goto fail;
    }

    GET_ADDRESS(library, scard, SCardEstablishContext);
    GET_ADDRESS(library, scard, SCardReleaseContext);
    GET_ADDRESS(library, scard, SCardBeginTransaction);
    GET_ADDRESS(library, scard, SCardEndTransaction);
    /* expands to SCardConnectA on Windows */
    GET_ADDRESS(library, scard, SCardConnect); 
    GET_ADDRESS(library, scard, SCardDisconnect);
    GET_ADDRESS(library, scard, SCardTransmit);
    GET_ADDRESS(library, scard, SCardReconnect);
    /* expands to SCardListReadersA on Windows  */
    GET_ADDRESS(library, scard, SCardListReaders); 
    /* expands to SCardStatusA on Windows */
    GET_ADDRESS(library, scard, SCardStatus);
#ifdef WIN32
    GET_ADDRESS(library, scard, SCardGetAttrib);
#endif
    /* SCardGetStatusChangeA */
    GET_ADDRESS(library, scard, SCardGetStatusChange);
    GET_ADDRESS(library, scard, SCardCancel);

    status = ckyShLibrary_getAddress( library,
	(void**) &scard->SCARD_PCI_T0_, MAKE_DLL_SYMBOL(g_rgSCardT0Pci));
    if( status != CKYSUCCESS ) {
        goto fail;
    }
    return scard;

fail:
    if (library) {
	ckyShLibrary_close(library);
    }
    free(scard);
    return NULL;
}
/*
 * Implement CKYReaderNameLists and CKYCardConnectionLists
 */
/* make the list code happy */
static void
CKYReaderName_Destroy(char *data) {
    free(data);
}

#include "cky_list.i"   /* implemnentation of the lists define by cky_list.h */
CKYLIST_IMPLEMENT(CKYReaderName, char *)
CKYLIST_IMPLEMENT(CKYCardConnection, CKYCardConnection *)


/*
 * CKReader objects represent Readers attached to the system.
 * The objects themselves are really SCard SCARD_READERSTATE objects.
 * These objects are used in 2 ways:
 *   1) the application creates static SCARD_READERSTATE's and use
 * CKYReader_Init() to initialize the structure. In this case
 * the application can call any of the reader 'methods' (functions
 * starting with CKReader) on these objects. When finished the
 * application is responsible for calling CKYReader_FreeData() to free
 * any data held by the reader object.
 *   2) Acquire an array of readers with CKYReader_CreateArray(). In this
 * case the application can call any method on any particular array member
 * In the end the Application is responsible for calling 
 * CKYReader_DestroyArray() to free the entire array.
 */

void
CKYReader_Init(SCARD_READERSTATE *reader)
{
    reader->szReader = NULL;
    reader->pvUserData = 0;
    reader->cbAtr = 0;
    reader->dwCurrentState = SCARD_STATE_UNAWARE;
}

void
CKYReader_FreeData(SCARD_READERSTATE *reader)
{
    if (reader->szReader) {
	free((void *)reader->szReader);
    }
    CKYReader_Init(reader);
}

CKYStatus 
CKYReader_SetReaderName(SCARD_READERSTATE *reader, const char *name)
{
    free((void *)reader->szReader);
    reader->szReader = strdup(name);
    return (reader->szReader)? CKYSUCCESS: CKYNOMEM;
}

const char *
CKYReader_GetReaderName(const SCARD_READERSTATE *reader)
{
    return reader->szReader;
}

/* see openSC or PCSC for the semantics of Known State and Event States */
CKYStatus 
CKYReader_SetKnownState(SCARD_READERSTATE *reader, unsigned long state)
{
    reader->dwCurrentState = state;
    return CKYSUCCESS;
}

unsigned long 
CKYReader_GetKnownState(const SCARD_READERSTATE *reader)
{
    return reader->dwCurrentState;
}

unsigned long 
CKYReader_GetEventState(const SCARD_READERSTATE *reader)
{
    return reader->dwEventState;
}

/* Caller must have init'ed the buffer before calling 
 * any data in the existing buffer is overwritten */
CKYStatus 
CKYReader_GetATR(const SCARD_READERSTATE *reader, CKYBuffer *buf)
{
    CKYStatus ret;

    ret = CKYBuffer_Resize(buf, reader->cbAtr);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    return CKYBuffer_Replace(buf, 0, reader->rgbAtr, reader->cbAtr);
}

SCARD_READERSTATE *
CKYReader_CreateArray(const CKYReaderNameList readerNames, 
					unsigned long *returnReaderCount)
{
    unsigned long i,j;
    unsigned long readerCount;
    SCARD_READERSTATE *readers;
    CKYStatus ret;

    readerCount=CKYReaderNameList_GetCount(readerNames);
    if (readerCount == 0) {
	return NULL;
    }
    readers = NEW(SCARD_READERSTATE, readerCount);
    if (readers == NULL) {
	return NULL;
    }

    for (i=0; i < readerCount; i++) {
	CKYReader_Init(&readers[i]);
	ret = CKYReader_SetReaderName(&readers[i],
			CKYReaderNameList_GetValue(readerNames,i));
	if (ret != CKYSUCCESS) {
	    break;
	}
    }
    if (ret != CKYSUCCESS) {
	for (j=0; j < i;  j++) {
	    CKYReader_FreeData(&readers[j]);
	}
	free(readers);
	return NULL;
    }
    if (returnReaderCount) {
 	*returnReaderCount=readerCount;
    }

    return readers;
}

/*
 * add more reader states to an existing reader state array. 
 * The existing reader will have a new pointer, which will be updated only
 * after the new one is complete, and before the old one is freed. The 'add'
 * array is not modified or freed.
 */ 
CKYStatus
CKYReader_AppendArray(SCARD_READERSTATE **array, unsigned long arraySize,
	 const char **readerNames, unsigned long numReaderNames)
{
    unsigned long i,j;
    SCARD_READERSTATE *readers;
    SCARD_READERSTATE *old;
    CKYStatus ret = CKYSUCCESS;

    readers = NEW(SCARD_READERSTATE, arraySize+numReaderNames);
    if (readers == NULL) {
	return CKYNOMEM;
    }
    /* copy the original readers, inheriting all the pointer memory */
    memcpy(readers, *array, arraySize*sizeof(SCARD_READERSTATE));

    /* initialize and add the new reader states. */
    for (i=0; i < numReaderNames; i++) {
	CKYReader_Init(&readers[i+arraySize]);
	ret = CKYReader_SetReaderName(&readers[i+arraySize],readerNames[i]);
	if (ret != CKYSUCCESS) {
	    break;
	}
    }

    /* we failed, only free the new reader states, ownership of the new
     * ones will revert back to the original */
    if (ret != CKYSUCCESS) {
	for (j=0; j < i;  j++) {
	    CKYReader_FreeData(&readers[j+arraySize]);
	}
	free(readers);
	return ret;
    }

    /* Now we swap the readers states */
    old = *array;
    *array = readers;
    /* it's now safe to free the old one */
    free(old);

    return CKYSUCCESS;
}

void
CKYReader_DestroyArray(SCARD_READERSTATE *reader, unsigned long readerCount)
{
    unsigned long i;

    for (i=0; i < readerCount; i++) {
	CKYReader_FreeData(&reader[i]);
    }
    free(reader);
}

/*
 * CKYCardContexts are wrapped access to the SCard Context, which is
 * part of the openSC/ Microsoft PCSC interface. Applications will
 * typically open one context to get access to the SCard Subsystem.
 * 
 * To protect ourselves from systems without the SCard library installed,
 * the SCard calls are looked up from the library and called through
 * a function pointer.
 */
struct _CKYCardContext {
    SCARDCONTEXT  context;
    SCard         *scard;
    unsigned long scope;
    unsigned long lastError;
};


static CKYStatus
ckyCardContext_init(CKYCardContext *ctx)
{
    static SCard *scard;

    ctx->lastError = 0;
    ctx->context = 0;
    if (!scard) {
	scard = ckySCard_Init();
	if (!scard) {
	   return CKYNOSCARD;
	}
    }
    ctx->scard = scard;
    return CKYSUCCESS;
}

static CKYStatus
ckyCardContext_release(CKYCardContext *ctx)
{
    unsigned long rv = ctx->scard->SCardReleaseContext(ctx->context);
    ctx->context = 0;
    if (rv != SCARD_S_SUCCESS) {
	ctx->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

static CKYStatus
ckyCardContext_establish(CKYCardContext *ctx, unsigned long scope)
{
    unsigned long rv;

    if (ctx->context) {
	ckyCardContext_release(ctx);
    }
    rv = ctx->scard->SCardEstablishContext(scope, NULL, NULL, &ctx->context);
    if (rv != SCARD_S_SUCCESS) {
	ctx->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYCardContext *
CKYCardContext_Create(unsigned long scope) 
{
    CKYCardContext *ctx;
    CKYStatus ret;

    ctx = NEW(CKYCardContext, 1);
    if (ctx == NULL) {
	return NULL;
    }
    ret = ckyCardContext_init(ctx);
    if (ret != CKYSUCCESS) {
	CKYCardContext_Destroy(ctx);
	return NULL;
    }
    ctx->scope = scope;
    ret = ckyCardContext_establish(ctx, scope);
#ifdef MAC
/* Apple won't establish a connnection if pcscd is not running. Because of
 * the way securityd controls pcscd, this may not necessarily be an error
 * condition. Detect this case and continue. We'll establish the connection
 * later..
 */
    if (ctx->lastError == SCARD_F_INTERNAL_ERROR) {
	ctx->context = 0; /* make sure it's not established */
	return ctx;
    }
#endif
    if (ret != CKYSUCCESS) {
	CKYCardContext_Destroy(ctx);
	return NULL;
    }
    return ctx;
}

CKYStatus 
CKYCardContext_Destroy(CKYCardContext *ctx)
{
    CKYStatus ret = CKYSUCCESS;
    if (ctx == NULL) {
	return CKYSUCCESS;
    }
    if (ctx->context) {
	ret = ckyCardContext_release(ctx);
    }
    free(ctx);
    return ret;
}

SCARDCONTEXT 
CKYCardContext_GetContext(const CKYCardContext *ctx)
{
    return ctx->context;
}

CKYStatus
CKYCardContext_ListReaders(CKYCardContext *ctx, CKYReaderNameList *readerNames)
{
    unsigned long readerLen;
    unsigned long rv;
    char * readerStr = NULL;
    char *cur;
    char ** readerList;
    int count,i;


    /* return NULL in the case nothing is found, or there is an error */
    *readerNames = NULL;

    /* if we aren't established yet, do so now */
    if (!ctx->context) {
	CKYStatus ret = ckyCardContext_establish(ctx, ctx->scope);
 	if (ret != CKYSUCCESS) {

#ifdef MAC
	    if (ctx->lastError == SCARD_F_INTERNAL_ERROR) {
		/* Still can't establish, just treat it as 'zero' readers */
		return CKYSUCCESS;
	    }
#endif
	    return ret;
	}
    }

    /* get the initial length */
    readerLen = 0;
    rv = ctx->scard->SCardListReaders(ctx->context, NULL /*groups*/, 
							NULL, &readerLen);
    /* handle the other errors from SCardListReaders */
    if (rv == SCARD_E_NO_READERS_AVAILABLE) {
	/* not really an error: there are no readers */
	return CKYSUCCESS;
    }

    if( rv != SCARD_S_SUCCESS ) {
	ctx->lastError = rv;
        return CKYSCARDERR;
    }

    /* if no readers, return OK and a NULL list */
    if (readerLen == 0) {
	return CKYSUCCESS;
    }

    /*
     * Keep trying to read in the buffer, allowing that the required buffer
     * length may change between calls to SCardListReaders.
     */
    do {
	if (readerLen < 1 || readerLen > CKY_OUTRAGEOUS_MALLOC_SIZE) {
	    return CKYNOMEM;
	}
	readerStr = NEW(char,readerLen);
	if (readerStr == NULL) {
	    return CKYNOMEM;
	}

        rv = ctx->scard->SCardListReaders(ctx->context, NULL /*groups*/,
                readerStr, &readerLen);

	/* we've found it, pop out with readerStr allocated */
	if (rv == SCARD_S_SUCCESS) {
            break;
	}

	/* Nope, free the reader we allocated */
	free(readerStr);
	readerStr = NULL;

    } while( rv == SCARD_E_INSUFFICIENT_BUFFER );

    /* handle the other errors from SCardListReaders */
    if (rv == SCARD_E_NO_READERS_AVAILABLE) {
	/* not really an error: there are no readers */
	ctx->lastError = SCARD_E_NO_READERS_AVAILABLE;
	return CKYSUCCESS;
    }
    if (rv != SCARD_S_SUCCESS) {
	/* stash the error and fail */
	ctx->lastError = rv;
	return CKYSCARDERR;
    }

    /* 
     * Windows returns the list of readers as a series of null terminated
     * strings, terminated with an additional NULL. For example, if there
     * are three readers name "Reader 1", "Reader 2", "Reader 3", the returned
     * readerStr would look like: "Reader 1\0Reader 2\0Reader N\0\0".
     *
     * We need to return a list of ReaderNames. This is currently a pointer
     * to an array of string pointers, terminated by a NULL.
     *
     * +--------------+
     * | Reader 1 ptr |   -> "Reader 1"
     * +--------------+
     * | Reader 2 ptr |   -> "Reader 2"
     * +--------------+
     * | Reader N ptr |   -> "Reader N"
     * +--------------+
     * |     NULL     |
     * +--------------+
     *
     * NOTE: This code explicitly knows the underlying format for
     *  CKYReaderNameLists defined in cky_list.i. If cky_list.i is changes,
     *  this code will need to be changed as well.
     */
    /* find the count of readers */
    for (cur = readerStr, count = 0; *cur; cur += strlen(cur)+1, count++ ) 
	/* Empty */ ;
    readerList = NEW(char *,count+1);
    if (readerList == NULL) {
	goto fail;
    }

    /* now copy the readers into the array */
    for (i=0, cur=readerStr; i < count ; cur+=strlen(cur) +1, i++) {
	readerList[i] = strdup(cur);
	if (readerList[i] == NULL) {
	    goto fail;
	}
    }
    readerList[count] = NULL;
    free(readerStr);;
    *readerNames = (CKYReaderNameList) readerList;
    return CKYSUCCESS;

fail:
    if (readerStr) {
	free(readerStr);
    }
    if (readerList) {
	CKYReaderNameList_Destroy((CKYReaderNameList) readerList);
    }
    return CKYNOMEM;
}

/*
 * The original C++ API had to very similiar functions that returned
 * either reader names or connections based on ATR. This is a single
 * function that can return both. The exported interface calls this
 * one with one of the lists set to NULL.
 *
 * NOTE: this function "knows" the underlying format for lists and
 * hand builds the related lists.
 */
CKYStatus 
ckyCardContext_findReadersByATR(CKYCardContext *ctx,
				CKYReaderNameList *returnReaders, 
				CKYCardConnectionList *returnConn, 
				const CKYBuffer *targetATR)
{
    CKYReaderNameList readerNames;
    CKYBuffer ATR;
    CKYCardConnection **connList = NULL;
    CKYCardConnection **connPtr  = NULL;
    char **readerList = NULL;
    char **readerPtr = NULL;
    int readerCount, i;
    CKYStatus ret;

    CKYBuffer_InitEmpty(&ATR);

    /* if we aren't established yet, do so now */
    if (!ctx->context) {
	ret = ckyCardContext_establish(ctx, ctx->scope);
 	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }

    /* initialize our returned values to empty */
    if (returnReaders) {
	*returnReaders = NULL;
    }
    if (returnConn) {
	*returnConn = NULL;
    }

    ret = CKYCardContext_ListReaders(ctx, &readerNames);
    if (ret != CKYSUCCESS) {
	return ret;
    }

    readerCount = CKYReaderNameList_GetCount(readerNames);

    /* none found, return success */
    if (readerCount == 0) {
	CKYReaderNameList_Destroy(readerNames);
	return CKYSUCCESS;
    }

    /* now initialize our name and connection lists */
    if (returnConn) {
	connList = NEW(CKYCardConnection *, readerCount);
	connPtr = connList;
	if (connList == NULL) {
	    goto fail;
	}
    }
    if (returnReaders) {
	readerList = NEW(char *, readerCount);
	readerPtr = readerList;
	if (readerList == NULL) {
	    goto fail;
	}
    }

    ret = CKYBuffer_Resize(&ATR, CKY_MAX_ATR_LEN);
    if (ret != CKYSUCCESS) {
	goto fail;
    }

    /* now walk the reader list trying to get connections */
    for (i=0; i < readerCount ; i++) {
	CKYCardConnection * conn = CKYCardConnection_Create(ctx);
	unsigned long state;
	const char *thisReader = CKYReaderNameList_GetValue(readerNames, i);


	if (!conn) {
	    goto loop;
	}
	ret = CKYCardConnection_Connect(conn, thisReader);
	if (ret != CKYSUCCESS) {
	    goto loop;
	}
	ret = CKYCardConnection_GetStatus(conn, &state, &ATR);
	if (ret != CKYSUCCESS) {
	    goto loop;
	}
	if (CKYBuffer_IsEqual(targetATR, &ATR)) {
	    if (connPtr) {
		*connPtr++ = conn; /* adopt */
		conn = NULL;
	    }
	    if (readerPtr) {
		*readerPtr++ = strdup(thisReader);
	    }
	}

loop:
	/* must happen each time through the loop */
	if (conn) {
	    CKYCardConnection_Destroy(conn);
	}
    }

    /* done with the reader names now */
    CKYReaderNameList_Destroy(readerNames);
    /* and the ATR buffer */
    CKYBuffer_FreeData(&ATR);

    /* terminate out lists and return them */
    if (readerPtr) {
	*readerPtr = NULL;
	*returnReaders = (CKYReaderNameList) readerList;
    }
    if (connPtr) {
	*connPtr = NULL;
	*returnConn = (CKYCardConnectionList) connList;
    }
    return CKYSUCCESS;

fail:
    if (readerNames) {
	CKYReaderNameList_Destroy(readerNames);
    }
    if (connList) {
	free(connList);
    }
    if (readerList) {
	free(readerList);
    }
    CKYBuffer_FreeData(&ATR);
    return CKYNOMEM;
}

CKYStatus 
CKYCardContext_FindCardsByATR(CKYCardContext *ctx,
		CKYCardConnectionList *cardList, const CKYBuffer *targetATR)
{
  return ckyCardContext_findReadersByATR(ctx, NULL, cardList, targetATR);
}

CKYStatus 
CKYCardContext_FindReadersByATR(CKYCardContext *ctx,
		CKYReaderNameList *readerNames, const CKYBuffer *targetATR)
{
  return ckyCardContext_findReadersByATR(ctx, readerNames, NULL, targetATR);
}

CKYCardConnection *
CKYCardContext_CreateConnection(CKYCardContext *ctx)
{
    return CKYCardConnection_Create(ctx);
}

CKYStatus
CKYCardContext_WaitForStatusChange(CKYCardContext *ctx, 
    		SCARD_READERSTATE *readers, unsigned long readerCount, 
							unsigned long timeout)
{
    unsigned long rv;

    /* if we aren't established yet, do so now */
    if (!ctx->context) {
	CKYStatus ret = ckyCardContext_establish(ctx, ctx->scope);
 	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }
    rv = ctx->scard->SCardGetStatusChange(ctx->context, timeout, 
							readers, readerCount);
    if (rv != SCARD_S_SUCCESS) {
	ctx->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYStatus 
CKYCardContext_Cancel(CKYCardContext *ctx)
{
    unsigned long rv;

    /* if we aren't established yet, we can't be in change status then */
    if (!ctx->context) {
	return CKYSUCCESS;
    }
    rv = ctx->scard->SCardCancel(ctx->context);

    if (rv != SCARD_S_SUCCESS) {
	ctx->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

unsigned long 
CKYCardContext_GetLastError(const CKYCardContext *ctx)
{
    return ctx->lastError;
}

/*
 * Connections represent the connection to the actual smart cards.
 * Applications usually has  one of these for each card inserted in
 * the system. Connections are where we can get information about
 * each card, as well as transmit commands (APDU's) to the card.
 */
/* In the originaly C++ library, lastError was set to the last return
 * code from any SCARD call. In this C version of the library, lastError
 * is the last non-successful SCARD call. lastError will be set
 * if the function returns CKYSCARDERR.
 */
struct _CKYCardConnection {
    const CKYCardContext *ctx;
    SCard            *scard;     /* cache a copy from the context */
    SCARDHANDLE      cardHandle;
    unsigned long    lastError;
    CKYBool           inTransaction;
};

static void
ckyCardConnection_init(CKYCardConnection *conn, const CKYCardContext *ctx)
{
    conn->ctx = ctx;
    conn->scard = ctx->scard;
    conn->cardHandle = 0;
    conn->lastError = 0;
    conn->inTransaction = 0;
}

CKYCardConnection *
CKYCardConnection_Create(const CKYCardContext *ctx)
{
    CKYCardConnection *conn;

    /* don't even try if we don't have a Card Context */
    if (ctx == NULL) {
	return NULL;
    }

    conn = NEW(CKYCardConnection, 1);
    if (conn == NULL) {
	return NULL;
    }
    ckyCardConnection_init(conn, ctx);
    return conn;
}


CKYStatus 
CKYCardConnection_Destroy(CKYCardConnection *conn)
{
    if (conn == NULL) {
	return CKYSUCCESS;
    }
    if (conn->inTransaction) {
	CKYCardConnection_EndTransaction(conn);
    }
    CKYCardConnection_Disconnect(conn);
    free(conn);
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_Connect(CKYCardConnection *conn, const char *readerName)
{
    CKYStatus ret;
    unsigned long rv;
    unsigned long protocol;

    ret = CKYCardConnection_Disconnect(conn);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    rv = conn->scard->SCardConnect( conn->ctx->context, readerName,
	SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &conn->cardHandle, &protocol);
    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_Disconnect(CKYCardConnection *conn)
{
    unsigned long rv;
    if (conn->cardHandle == 0) {
	return CKYSUCCESS;
    }
    rv = conn->scard->SCardDisconnect( conn->cardHandle, SCARD_LEAVE_CARD);
    conn->cardHandle = 0;
    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYBool 
CKYCardConnection_IsConnected(const CKYCardConnection *conn)
{
    return (conn->cardHandle != 0);
}

CKYStatus 
ckyCardConnection_reconnectRaw(CKYCardConnection *conn, unsigned long init)
{
    unsigned long rv;
    unsigned long protocol;

    rv = conn->scard->SCardReconnect(conn->cardHandle,
	SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, init, &protocol);
    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_Reconnect(CKYCardConnection *conn)
{
    return ckyCardConnection_reconnectRaw(conn, SCARD_LEAVE_CARD);
}

CKYStatus CKYCardConnection_Reset(CKYCardConnection *conn)
{
    return ckyCardConnection_reconnectRaw(conn, SCARD_RESET_CARD);
}

CKYStatus 
CKYCardConnection_BeginTransaction(CKYCardConnection *conn)
{
    unsigned long rv;
    rv = conn->scard->SCardBeginTransaction(conn->cardHandle);
    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
 	return CKYSCARDERR;
    }
    conn->inTransaction = 1;
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_EndTransaction(CKYCardConnection *conn)
{
    unsigned long rv;
    if (!conn->inTransaction) {
	return CKYSUCCESS; /* C++ library returns success in this case, but
		           * it may be better to return an error ? */
    }
    rv = conn->scard->SCardEndTransaction(conn->cardHandle, SCARD_LEAVE_CARD);
    conn->inTransaction = 0;
    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
 	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_TransmitAPDU(CKYCardConnection *conn, CKYAPDU *apdu,
							CKYBuffer *response)
{
    CKYStatus ret;
    unsigned long rv;

    ret = CKYBuffer_Resize(response, CKYAPDU_MAX_LEN);
    if (ret != CKYSUCCESS) {
	return ret;
    }

    rv = conn->scard->SCardTransmit(conn->cardHandle, 
	conn->scard->SCARD_PCI_T0_,
	CKYBuffer_Data(&apdu->apduBuf), CKYBuffer_Size(&apdu->apduBuf), 
	NULL, response->data, &response->len);

    if (rv != SCARD_S_SUCCESS) {
	conn->lastError =rv;
	return CKYSCARDERR;
    }

    return CKYSUCCESS;
}

CKYStatus
CKYCardConnection_ExchangeAPDU(CKYCardConnection *conn, CKYAPDU *apdu,
							CKYBuffer *response)
{
    CKYStatus ret;

    ret = CKYCardConnection_TransmitAPDU(conn, apdu, response);
    if (ret != CKYSUCCESS) {
	return ret;
    }

    if (CKYBuffer_Size(response) == 2 && CKYBuffer_GetChar(response,0) == 0x61) {
	/* get the response */
	CKYAPDU getResponseAPDU;

	CKYAPDU_Init(&getResponseAPDU);
	CKYAPDU_SetCLA(&getResponseAPDU, 0x00);
	CKYAPDU_SetINS(&getResponseAPDU, 0xc0);
	CKYAPDU_SetP1(&getResponseAPDU, 0x00);
	CKYAPDU_SetP2(&getResponseAPDU, 0x00);
	CKYAPDU_SetReceiveLen(&getResponseAPDU, CKYBuffer_GetChar(response,1));
	ret = CKYCardConnection_TransmitAPDU(conn, &getResponseAPDU, response);
	CKYAPDU_FreeData(&getResponseAPDU);
    }
    return ret;
}

CKYStatus 
CKYCardConnection_GetStatus(CKYCardConnection *conn,
				unsigned long *state, CKYBuffer *ATR)
{
    unsigned long readerLen = 0;
    unsigned long protocol;
    unsigned long rv;
    CKYSize atrLen;
    char *readerStr;
    CKYStatus ret;


    /*
     * Get initial length. We have to do all this because the Muscle
     * implementation of PCSC requires us to supply a non-NULL argument
     * for readerName before it will tell us the ATR, which is all we really
     * care about.
     */
    rv = conn->scard->SCardStatus(conn->cardHandle, 
	    NULL /*readerName*/, &readerLen, state, &protocol, NULL, &atrLen);
    if ( rv != SCARD_S_SUCCESS ) {
	conn->lastError = rv;
        return CKYSCARDERR;
    }

    do {
	if (readerLen < 1 || readerLen > CKY_OUTRAGEOUS_MALLOC_SIZE) {
	    return CKYNOMEM;
	}
	/* Mac & Linux return '0' or ATR length, just use the max value */
	if (atrLen == 0) {
	    atrLen = CKY_MAX_ATR_LEN;
	}
	if (atrLen < 1 || atrLen > CKY_OUTRAGEOUS_MALLOC_SIZE) {
	    return CKYNOMEM;
	}
	ret = CKYBuffer_Resize(ATR, atrLen);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
	readerStr = NEW(char, readerLen);
	if (readerStr == NULL) {
	    return CKYNOMEM;
	}

	rv = conn->scard->SCardStatus(conn->cardHandle, readerStr, &readerLen,
                state, &protocol, ATR->data, &atrLen);
	ATR->len = atrLen;
	free(readerStr);
    } while (rv == SCARD_E_INSUFFICIENT_BUFFER);

    if (rv != SCARD_S_SUCCESS) {
	conn->lastError = rv;
	return CKYSCARDERR;
    }
    return CKYSUCCESS;
}

CKYStatus 
CKYCardConnection_GetAttribute(CKYCardConnection *conn,
				unsigned long attrID, CKYBuffer *attrBuf)
{
#ifdef WIN32
    unsigned long len = 0;
    unsigned long rv;
    
    /*
     * Get initial length. We have to do all this because the Muscle
     * implementation of PCSC requires us to supply a non-NULL argument
     * for readerName before it will tell us the ATR, which is all we really
     * care about.
     */
    rv = conn->scard->SCardGetAttrib(conn->cardHandle, attrID, NULL, &len);
    if ( rv != SCARD_S_SUCCESS ) {
	conn->lastError = rv;
        return CKYSCARDERR;
    }
    CKYBuffer_Resize(attrBuf, len);

    rv = conn->scard->SCardGetAttrib(conn->cardHandle, attrID, 
						attrBuf->data, &attrBuf->len);
    if( rv != SCARD_S_SUCCESS ) {
	conn->lastError = rv;
        return CKYSCARDERR;
    }
    return CKYSUCCESS;
#else
    conn->lastError = -1;
    return CKYSCARDERR;
#endif
}

const CKYCardContext *
CKYCardConnection_GetContext(const CKYCardConnection *conn)
{
    return conn->ctx;
}

unsigned long 
CKYCardConnection_GetLastError(const CKYCardConnection *conn)
{
    return conn->lastError;
}
