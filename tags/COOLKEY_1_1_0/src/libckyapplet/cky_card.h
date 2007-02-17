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

#ifndef CKY_CARD_H
#define CKY_CARD_H 1

#include <winscard.h>

#include "cky_base.h"
#include "cky_list.h"

/*
 * hide the structure of CardConnections and CardContexts
 */
typedef struct _CKYCardContext CKYCardContext;
typedef struct _CKYCardConnection CKYCardConnection;

/*
 * define CKYReaderNameList, CKYReaderNameIterator, CKYCardConnectionList, and
 * CKYCardConnectionIterator, and their associated functions.
 * See cky_list.h for these functions .
 */

CKYLIST_DECLARE(CKYReaderName, char *)
CKYLIST_DECLARE(CKYCardConnection, CKYCardConnection *)

CKY_BEGIN_PROTOS
void CKYReader_Init(SCARD_READERSTATE_A *reader);
void CKYReader_FreeData(SCARD_READERSTATE_A *reader);

/*
 * "Accessors": for SCARD_READERSTATE_A structure as a class.
 * These functions take an SCARD_READERSTATE_A which can also be referenced
 * directly.
 */
CKYStatus CKYReader_SetReaderName(SCARD_READERSTATE_A *reader, const char *name);
const char *CKYReader_GetReaderName(const SCARD_READERSTATE_A *reader);
CKYStatus CKYReader_SetKnownState(SCARD_READERSTATE_A *reader, 
						unsigned long state);
unsigned long CKYReader_GetKnownState(const SCARD_READERSTATE_A *reader);
unsigned long CKYReader_GetEventState(const SCARD_READERSTATE_A *reader);
CKYStatus CKYReader_GetATR(const SCARD_READERSTATE_A *reader, CKYBuffer *buf);
/* create an array of READERSTATEs from a LIST of Readers */
SCARD_READERSTATE_A *CKYReader_CreateArray(const CKYReaderNameList readerNames, 
					  unsigned long *readerCount);
/* frees the reader, then the full array */
void CKYReader_DestroyArray(SCARD_READERSTATE *reader, unsigned long count);
/* add more elements to a ReaderState array*/ 
CKYStatus
CKYReader_AppendArray(SCARD_READERSTATE **array, unsigned long arraySize,
	 const char **readerNames, unsigned long numReaderNames);

/*
 * card contexts wrap Microsoft's SCARDCONTEXT.
 */
/* create a new one. SCOPE must be SCOPE_USER */
CKYCardContext *CKYCardContext_Create(unsigned long scope);
/* destroy an existing one */
CKYStatus CKYCardContext_Destroy(CKYCardContext *context);
/* get the Windows handle associated with this context */
SCARDCONTEXT CKYCardContext_GetContext(const CKYCardContext *context);
/* Get a list of the installed readers */
CKYStatus CKYCardContext_ListReaders(CKYCardContext *context, 
						CKYReaderNameList *readerNames);
/* get a list of card connections for cards matching our target ATR */
CKYStatus CKYCardContext_FindCardsByATR(CKYCardContext *context,
				CKYCardConnectionList *cardList, 
				const CKYBuffer *targetATR);
/* get a list of readers with attached cards that match our target ATR */
CKYStatus CKYCardContext_FindReadersByATR(CKYCardContext *context,
				CKYReaderNameList *readerNames, 
				const CKYBuffer *targetATR);
/* return if any of the readers in our array has changed in status */
CKYStatus CKYCardContext_WaitForStatusChange(CKYCardContext *context,
				SCARD_READERSTATE_A *readers,
				unsigned long readerCount,
				unsigned long timeout);
/* cancel any current operation (such as wait for status change) on this
 * context */
CKYStatus CKYCardContext_Cancel(CKYCardContext *context);
/* get the last underlying Windows SCARD error */
unsigned long CKYCardContext_GetLastError(const CKYCardContext *context);

/*
 * manage the actual connection to a card.
 */
/* create a connection. A connection is not associated with a reader
 * until CKYCardConnection_Connect() is called.
 */
CKYCardConnection *CKYCardConnection_Create(const CKYCardContext *context);
CKYStatus CKYCardConnection_Destroy(CKYCardConnection *connection);
CKYStatus CKYCardConnection_BeginTransaction(CKYCardConnection *connection);
CKYStatus CKYCardConnection_EndTransaction(CKYCardConnection *connection);
CKYStatus CKYCardConnection_TransmitAPDU(CKYCardConnection *connection,
					CKYAPDU *apdu,
					CKYBuffer *response);
CKYStatus CKYCardConnection_ExchangeAPDU(CKYCardConnection *connection,
					CKYAPDU *apdu,
					CKYBuffer *response);
CKYStatus CKYCardConnection_Connect(CKYCardConnection *connection, 
					const char *readerName);
CKYStatus CKYCardConnection_Disconnect(CKYCardConnection *connection);
CKYBool CKYCardConnection_IsConnected(const CKYCardConnection *connection);
CKYStatus CKYCardConnection_Reconnect(CKYCardConnection *connection);
CKYStatus CKYCardConnection_GetStatus(CKYCardConnection *connection,
				unsigned long *state, CKYBuffer *ATR);
CKYStatus CKYCardConnection_GetAttribute(CKYCardConnection *connection,
				unsigned long attrID, CKYBuffer *attrBuf);
CKYStatus CKYCardConnection_Reset(CKYCardConnection *connection);
const CKYCardContext *CKYCardConnection_GetContext(const CKYCardConnection *cxt);
unsigned long CKYCardConnection_GetLastError(const CKYCardConnection *context);

CKY_END_PROTOS

#endif /* CKY_CARD_H */
