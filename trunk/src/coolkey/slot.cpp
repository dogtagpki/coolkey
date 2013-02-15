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

#include <string>
#include "mypkcs11.h"
#include <stdio.h>
#include <assert.h>
#include "log.h"
#include "PKCS11Exception.h"
#include <winscard.h>
#include "slot.h"
#include "zlib.h"
#include "params.h"

#include "machdep.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))



#ifdef DEBUG
#define PRINTF(args) printf args
#else
#define PRINTF(args)
#endif
// #define DISPLAY_WHOLE_GET_DATA 1


// The Cyberflex Access 32k egate ATR
const CKYByte ATR[] =
{ 0x3b, 0x75, 0x94, 0x00, 0x00, 0x62, 0x02, 0x02, 0x02, 0x01 };
const CKYByte ATR1[] =
{ 0x3b, 0x75, 0x94, 0x00, 0x00, 0x62, 0x02, 0x02, 0x03, 0x01 };
const CKYByte ATR3[] = 
{ 0x3b, 0x76, 0x94, 0x00, 0x00, 0xff, 0x62, 0x76, 0x01, 0x00, 0x00 };
/* RSA SecurID */
const CKYByte ATR2[] = 
{  0x3B, 0x6F, 0x00, 0xFF, 0x52, 0x53, 0x41, 0x53, 0x65, 0x63, 0x75, 0x72,
   0x49, 0x44, 0x28, 0x52, 0x29, 0x31, 0x30 };

SlotList::SlotList(Log *log_) : log(log_)
{
    // initialize things to NULL so we can recover from an exception
    slots = NULL;
    numSlots = 0;
    readerStates = NULL;
    numReaders = 0;
    context = NULL;
    shuttingDown  = FALSE;

    try {

        context = CKYCardContext_Create(SCARD_SCOPE_USER);
        if( context == NULL) {
            throw PKCS11Exception(CKR_GENERAL_ERROR,
                "Failed to create card context\n");
        }
	updateSlotList();
    } catch( PKCS11Exception &) {
        CKYCardContext_Destroy(context);
	if (readerStates) {
	    CKYReader_DestroyArray(readerStates, numReaders);
	}
        throw;
    }
}

SlotList::~SlotList()
{
    if( slots ) {
        assert( numSlots > 0 );
        for( unsigned int i=0; i < numSlots; ++i ) {
            delete slots[i];
        }
        delete [] slots;
        slots = NULL;
        numSlots = 0;
    }
    if (readerStates) {
	CKYReader_DestroyArray(readerStates, numReaders);
	readerStates = NULL;
        numReaders = 0;
    }
    if (context) {
	CKYCardContext_Destroy(context);
 	context = NULL;
    }
}
void
SlotList::shutdown()
{
   shuttingDown = TRUE;
   CKYCardContext_Cancel(context);
}

void
SlotList::updateSlotList()
{
    Slot **newSlots = NULL;
    Slot **oldSlots = NULL;

    readerListLock.getLock();

    updateReaderList();

    if (numSlots == numReaders) {
        readerListLock.releaseLock();
	return;
    }
    assert(numSlots < numReaders);
    if (numSlots > numReaders) {
        readerListLock.releaseLock();
	throw PKCS11Exception(CKR_GENERAL_ERROR,
			"Reader and slot count inconsistant\n");
    }

    try {
	newSlots = new Slot*[numReaders];
        if (newSlots == NULL ) 
	    throw PKCS11Exception(CKR_HOST_MEMORY);
	memset(newSlots, 0, numReaders*sizeof(Slot*));

        memcpy(newSlots, slots, sizeof(slots[0]) * numSlots);

	for (unsigned int i=numSlots; i < numReaders; i++) {
	    newSlots[i] = new
		Slot(CKYReader_GetReaderName(&readerStates[i]), log, context);
	}

	oldSlots = slots;
	slots = newSlots;  // update the pointer first 
	numSlots = numReaders; // now update the count 
	if (oldSlots) {    // ok we can free the old value now
	    delete [] oldSlots;
	}
    } catch( PKCS11Exception &) {
        // Recover by deleting everything that was created.
        if( newSlots ) {
            assert(numSlots < numReaders );
            for( unsigned int i=numSlots; i < numReaders; ++i ) {
                if( newSlots[i] ) {
                    delete newSlots[i];
                }
            }
            delete [] newSlots;
        }
        readerListLock.releaseLock();
        throw;
    }
    readerListLock.releaseLock();
	
}

bool
SlotList::readerExists(const char *readerName, unsigned int *hint)
{
    unsigned int start = 0;
    unsigned int i;

    if (hint && (*hint < numReaders)) {
	start = *hint;
    }

    /*
     * We use 'hint' as a way of deciding where to
     * start. This way we can handle the normal case where the name list
     * and the readerState matches one for one with a single string compare.
     */ 
    for (i=start; i < numReaders; i++) {
	if (strcmp(CKYReader_GetReaderName(&readerStates[i]),readerName) == 0) {
	    if (hint) {
		*hint = i+1;
	    }
	    return TRUE;
	}
    }
    /* we guessed wrong, check the first part of the reader states */
    for (i=0; i < start; i++) {
	if (strcmp(CKYReader_GetReaderName(&readerStates[i]),readerName) == 0) {
	    if (hint) {
		*hint = i+1;
	    }
	    return TRUE;
	}
    }
    /* OK, we've found a genuinely new reader */
    return FALSE;
}

bool
SlotList::readerNameExistsInList(const char *readerName,CKYReaderNameList *readerNameList)
{
    if( !readerName || !readerNameList) {
        return FALSE;
    }

    int i = 0;
    int readerNameCnt = CKYReaderNameList_GetCount(*readerNameList);

    const char *curReaderName = NULL;
    for(i=0; i < readerNameCnt; i++) {
        curReaderName = CKYReaderNameList_GetValue(*readerNameList,i);

        if(!strcmp(curReaderName,readerName)) {
            return TRUE;
        }
        
    }
    
    return FALSE;
}

/*
 * you need to hold the ReaderList Lock before you can update the ReaderList
 */
#define MAX_READER_DELTA 4
void
SlotList::updateReaderList()
{
    CKYReaderNameList readerNames = NULL;

    CKYStatus status = CKYCardContext_ListReaders(context, &readerNames);
    if ( status != CKYSUCCESS ) {
	/* if the service is stopped, treat it as if we have no readers */
 	if ((CKYCardContext_GetLastError(context) != SCARD_E_NO_SERVICE) && 
	    (CKYCardContext_GetLastError(context) != SCARD_E_SERVICE_STOPPED)) {
	    throw PKCS11Exception(CKR_GENERAL_ERROR,
                 "Failed to list readers: 0x%x\n", 
 				CKYCardContext_GetLastError(context));
	}

    }

    if (!readerStates) {
	/* fresh Reader State list, just create it */
	readerStates = CKYReader_CreateArray(readerNames, (CKYSize *)&numReaders);

	/* if we have no readers, make sure we have at least one to keep things
	 * happy */
	if (readerStates == NULL &&
			 CKYReaderNameList_GetCount(readerNames) == 0) {
	    readerStates = (SCARD_READERSTATE *)
				malloc(sizeof(SCARD_READERSTATE));
	    if (readerStates) {
		CKYReader_Init(readerStates);
		status = CKYReader_SetReaderName(readerStates, "E-Gate 0 0");
		if (status != CKYSUCCESS) {
 		    CKYReader_DestroyArray(readerStates, 1);
		    readerStates = NULL;
		} else {
		    numReaders = 1;
		}
	    }
	}
	CKYReaderNameList_Destroy(readerNames);
	        
	if (readerStates == NULL) {
	    throw PKCS11Exception(CKR_HOST_MEMORY,
				"Failed to allocate ReaderStates\n");
	}
	return;
    }

    /* it would be tempting at this point just to see if we have more readers
     * then specified previously. The problem with this is it is possible that
     * some readers have been deleted, so the only way to tell if we have
     * new readers is to see if there are any readers on the list that we
     * don't recognize.
     */

    /* first though, let's check to see if any previously removed readers have 
     * come back from the dead. If the ignored bit has been set, we do not need
     * it any more.
    */

    const char *curReaderName = NULL;
    unsigned long knownState = 0;
    for(unsigned int ri = 0 ; ri < numReaders; ri ++)  {
       
        knownState = CKYReader_GetKnownState(&readerStates[ri]);
        if( !(knownState & SCARD_STATE_IGNORE))  {
            continue;
        }
 
        curReaderName =  CKYReader_GetReaderName(&readerStates[ri]); 
        if(readerNameExistsInList(curReaderName,&readerNames)) {
            CKYReader_SetKnownState(&readerStates[ri], knownState & ~SCARD_STATE_IGNORE); 
                 
        }
    } 

    const char *newReadersData[MAX_READER_DELTA];
    const char **newReaders = &newReadersData[0];
    unsigned int newReaderCount = 0;
    unsigned int hint = 0;

    try {
	CKYReaderNameIterator iter;

	for (iter = CKYReaderNameList_GetIterator(readerNames);
				!CKYReaderNameIterator_End(iter); 
				iter = CKYReaderNameIterator_Next(iter)) {
	    const char *thisReaderName = CKYReaderNameIterator_GetValue(iter);
	    if (!readerExists(thisReaderName, &hint)) {
		if (newReaderCount == MAX_READER_DELTA) {
		    /* oops, we overflowed our buffer, alloc a new one right 
		     * quick. This code is very unlikely, so it's not fast, 
		     * but it's  meant to keep working, even in this weird 
		     * condition. NOTE: it assumes that we can't have any
		     * more  new readers than candidate readers we are
		     * checking */
		    int maxReaders = CKYReaderNameList_GetCount(readerNames);
		    assert(maxReaders > MAX_READER_DELTA);
		    newReaders = new const char *[maxReaders]; 
		    if (!newReaders) {
			throw PKCS11Exception(CKR_HOST_MEMORY,
			   "Could allocate space for %d new readers\n", 
								maxReaders);
		    }
		    memcpy(newReaders, newReadersData, 
				MAX_READER_DELTA*sizeof(newReadersData[0]));
		}
		newReaders[newReaderCount++] = thisReaderName;
	    }
	}
	/* OK, we haven't added any new readers, blow out now */
	if (newReaderCount == 0) {
	    CKYReaderNameList_Destroy(readerNames);
	    return;
	}

	status = CKYReader_AppendArray(&readerStates, numReaders,
				newReaders, newReaderCount);
	if (status != CKYSUCCESS) {
	    throw PKCS11Exception(CKR_GENERAL_ERROR,
			"Couldn't append %d new reader states\n",
				newReaderCount);
	}
	numReaders += newReaderCount;

	CKYReaderNameList_Destroy(readerNames);
	/* free newReaders if w were forced to alloc it */
	if (newReaders != &newReadersData[0]) {
	    delete [] newReaders;
	}
	return;

    } catch( PKCS11Exception &) {
	CKYReaderNameList_Destroy(readerNames);
	/* free newReaders if w were forced to alloc it */
	if (newReaders != &newReadersData[0]) {
	    delete [] newReaders;
	}

        throw;
    }
}
    

Slot::Slot(const char *readerName_, Log *log_, CKYCardContext* context_)
    : log(log_), readerName(NULL), personName(NULL), manufacturer(NULL),
	slotInfoFound(false), context(context_), conn(NULL), state(UNKNOWN), 
	isVersion1Key(false), needLogin(false), fullTokenName(false), 
	mCoolkey(false), mOldCAC(false), mCACLocalLogin(false),
	pivContainer(-1), pivKey(-1),
#ifdef USE_SHMEM
	shmem(readerName_),
#endif
	sessionHandleCounter(1), objectHandleCounter(1)
{

  tokenFWVersion.major = 0;
  tokenFWVersion.minor = 0;


  try {
    conn = CKYCardConnection_Create(context);
    if( conn == 0 ) {
        throw PKCS11Exception(CKR_GENERAL_ERROR);
    }
    hwVersion.major = 255;
    hwVersion.minor = 255;

    //Initialize login state for both Version 1 keys and older keys
    reverify = false;
    nonceValid = false;
    loggedIn = false;
    pinCache.invalidate();
    pinCache.clearPin();
    //readSlotInfo();
    manufacturer = strdup("Unknown");
    if (!manufacturer) {
	throw PKCS11Exception(CKR_HOST_MEMORY);
    }
    readerName = strdup(readerName_);
    if (!readerName) {
	throw PKCS11Exception(CKR_HOST_MEMORY);
    }
    CKYStatus ret = CKYBuffer_InitFromLen(&nonce, NONCE_SIZE);
    if (ret != CKYSUCCESS) {
	throw PKCS11Exception(CKR_HOST_MEMORY);
    }
    CKYBuffer_InitEmpty(&cardATR);
    CKYBuffer_InitEmpty(&mCUID);
    for (int i=0; i < MAX_CERT_SLOTS; i++) {
	CKYBuffer_InitEmpty(&cardAID[i]);
    }
  } catch(PKCS11Exception &) {
	if (conn) {
	    CKYCardConnection_Destroy(conn);
	}
	if (manufacturer) {
	    free(manufacturer);
	}
	if (readerName) {
	    free(readerName);
	}
        throw;
  }
}

void
Slot::readSlotInfo(void)
{
#ifdef WIN32  /* Mac doesn't have the SCardGetAttrib function */
    CKYStatus status;
    CKYBuffer attrBuf;

    CKYBuffer_InitEmpty(&attrBuf);
    status = CKYCardConnection_GetAttribute(conn, 
			SCARD_ATTR_VENDOR_IFD_VERSION, &attrBuf);
    if (status == CKYSUCCESS) {
	const CKYByte *type = CKYBuffer_Data(&attrBuf);

	if (CKYBuffer_Size(&attrBuf) == sizeof(unsigned long)) {
	    /* buffer data is returned in machine order, not network or
	     * applet order */
	    unsigned long version = *(unsigned long *)type;
	    hwVersion.major = (CK_BYTE) (version >> 24) & 0xff;
	    hwVersion.minor = (CK_BYTE) (version >> 16) & 0xff;
	}
        status = CKYCardConnection_GetAttribute(conn, 
					SCARD_ATTR_VENDOR_NAME, &attrBuf);
	if (status == CKYSUCCESS) {
	    free(manufacturer);
	    /* make sure manufacturer is NULL terminated */
	    CKYBuffer_AppendChar(&attrBuf,0);
	    manufacturer = strdup((const char *)CKYBuffer_Data(&attrBuf));
	    slotInfoFound = true;
	} 
    } else {
	PRINTF(("readSlotInfo failed\n"));
    }
    CKYBuffer_FreeData(&attrBuf);
#endif  /* WIN32 */
}

Slot::~Slot()
{
    if (conn) {
	CKYCardConnection_Destroy(conn);
    }
    if (readerName) {
	free(readerName);
    }
    if (personName) {
	free(personName);
    }
    if (manufacturer) {
	free(manufacturer);
    }
    CKYBuffer_FreeData(&nonce);
    CKYBuffer_FreeData(&cardATR);
    CKYBuffer_FreeData(&mCUID);
    for (int i=0; i < MAX_CERT_SLOTS; i++) {
	CKYBuffer_FreeData(&cardAID[i]);
    }
}

template <class C>
class ArrayFreer {
  private:
    C *ptr;
  public:
    ArrayFreer(C* cptr) : ptr(cptr) { }
    ~ArrayFreer() {
        if( ptr ) {
            delete [] ptr;
        }
    }
    void release() { ptr = NULL; }
};

CK_RV
SlotList::getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
         CK_ULONG_PTR pulCount) 
{
    CK_RV rv = CKR_OK;
    unsigned int i;

    if( pulCount == NULL ) {
        throw PKCS11Exception(CKR_ARGUMENTS_BAD);
    }

    if (pSlotList == NULL) {
        updateSlotList();
    }

    //
    // first, figure out which slots have tokens present
    //
    bool * tokenIsPresent = new bool[numSlots];
    if( tokenIsPresent == NULL ) {
        throw PKCS11Exception(CKR_HOST_MEMORY);
    }
    ArrayFreer<bool> deleteTokIsPres(tokenIsPresent);

    unsigned int numPresent = 0;
    for( i = 0; i < numSlots; ++i ) {
        tokenIsPresent[i] = slots[i]->isTokenPresent();
        numPresent += tokenIsPresent[i];
    }

    //
    // now fill in the slot list if it was supplied
    //
    if( pSlotList != NULL ) {
        if( tokenPresent ) {
            // only slots with tokens present
            if( *pulCount >= numPresent ) {
                // we have enough space to copy the slot IDs
                unsigned int j;
                for( i=0, j=0; i < numSlots; ++i ) {
                    if( tokenIsPresent[i] ) {
                        assert(j < numPresent);
                        pSlotList[j++] = slotIndexToID(i);
                    }
                }
                assert( j == numPresent );
            } else {
                // not enough space
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            // all slots, even without tokens present
            if( *pulCount >= numSlots ) {
                // we have enough space to copy the slot IDs
                for( i=0; i < numSlots; ++i ) {
                    pSlotList[i] = slotIndexToID(i);
                }
            } else {
                // not enough space
                rv = CKR_BUFFER_TOO_SMALL;
            }
        }
    }

    // set the number of slots
    if( tokenPresent ) {
        *pulCount = numPresent;
    } else {
        *pulCount = numSlots;
    }

    return rv;
}

bool
Slot::getPIVLoginType(void)
{
    CKYStatus status;
    CKYISOStatus apduRC;
    CKYBuffer buffer;
    bool local = true;

    CKYBuffer_InitEmpty(&buffer);

    /* get the discovery object */
    status = PIVApplet_GetCertificate(conn, &buffer, 0x7e, &apduRC);
    if (status != CKYSUCCESS) {
	/* Discovery object optional, PIV defaults to local */
	goto done;
    }
    /* techically we probably should parse out the TLVs, but the PIV
     * specifies exactly what they should be, so we know exactly which
     * byte to look at */
    if ((CKYBuffer_Size(&buffer) >= 20) && 
			(CKYBuffer_GetChar(&buffer,17) == 0x60)) {
	/* This tells us we should use global login for this piv card */
	local = false;
    }
done:
    CKYBuffer_FreeData(&buffer);
    return true;
}

void
Slot::connectToToken()
{
    CKYStatus status = CKYSCARDERR;
    OSTime time = OSTimeNow();

    mCoolkey = 0;
    tokenFWVersion.major = 0;
    tokenFWVersion.minor = 0;

    // try to connect to the card
    if( ! CKYCardConnection_IsConnected(conn) ) {
        int i = 0;
    //for cranky readers try again a few more times
        status = CKYSCARDERR;
        while( i++ < 5 && status != CKYSUCCESS )
        {
            status = CKYCardConnection_Connect(conn, readerName);
            if( status != CKYSUCCESS && 
                CKYCardConnection_GetLastError(conn) == SCARD_E_PROTO_MISMATCH ) 
            {
                log->log("Unable to connect to token status %d ConnGetGetLastError %x .\n",status,CKYCardConnection_GetLastError(conn));

            }
            else
            {
                break;
            }
            OSSleep(100000);
        }

        if( status != CKYSUCCESS)
        {
            state = UNKNOWN;
            return;
        }
    }

    log->log("time connect: Connect Time %d ms\n", OSTimeNow() - time);
    if (!slotInfoFound) {
	readSlotInfo();
    }
    log->log("time connect: Read Slot %d ms\n", OSTimeNow() - time);

    // Get card state. See if it is present, and if the ATR matches
    unsigned long cardState;
    status = CKYCardConnection_GetStatus(conn, &cardState, &cardATR);
    if( status != CKYSUCCESS ) {
        disconnect();
        return;
    }
    log->log("time connect: connection status %d ms\n", OSTimeNow() - time);
    if( cardState & SCARD_PRESENT ) {
        state = CARD_PRESENT;
    }

    if (Params::hasParam("noAppletOK"))
    {      
        state |=  APPLET_SELECTABLE;
	mCoolkey = 1;
    }

    /* support CAC card. identify the card based on applets, not the ATRS */
    state |= ATR_MATCH;

    /* our production cards should "ALWAYS" have an applet, even if it
     * doesn't exit */
    if ( CKYBuffer_DataIsEqual(&cardATR, ATR3, sizeof (ATR3)) ) {
        state |= ATR_MATCH | APPLET_SELECTABLE;
	mCoolkey = 1;

    }

    Transaction trans;
    status = trans.begin(conn);

    /* CAC card are cranky after they are first inserted.
     *  don't continue until we can convince the tranaction to work */
    for (int count = 0; count < 10 && status == CKYSCARDERR 
       && CKYCardConnection_GetLastError(conn) == SCARD_W_RESET_CARD; count++) {
	log->log("CAC Card Reset detected retry %d: time %d ms\n", count,
		OSTimeNow() - time);
        CKYCardConnection_Disconnect(conn);
	OSSleep(100000); /* 100 ms */
        status = CKYCardConnection_Connect(conn, readerName);
	if (status != CKYSUCCESS) {
	   continue;
	}
	status = trans.begin(conn);
    }

    /* Can't get a transaction, give up */
    if (status != CKYSUCCESS) {
        log->log("Transaction Failed 0x%x\n", status);
	handleConnectionError();
    }

    // see if the applet is selectable

    log->log("time connnect: Begin transaction %d ms\n", OSTimeNow() - time);
    status = PIVApplet_Select(conn, NULL);
    if (status != CKYSUCCESS) {
	goto piv_loser;
    }
    /* Card is a PIV card */
    state |= PIV_CARD | APPLET_SELECTABLE | APPLET_PERSONALIZED;
    isVersion1Key = 0;
    needLogin = 1;
    mCoolkey = 0;
    mOldCAC = 0;
    mCACLocalLogin = getPIVLoginType();
    return;
piv_loser:
    log->log("PIV Select failed 0x%x\n", status);
    status = CKYApplet_SelectCoolKeyManager(conn, NULL);
    if (status != CKYSUCCESS) {
	goto coolkey_loser;
    }
    mCoolkey = 1;
    log->log("time connect: Select Applet %d ms\n", OSTimeNow() - time);

    state |= APPLET_SELECTABLE;

    // now see if the applet is personalized
    CKYAppletRespGetLifeCycleV2 lifeCycleV2;
    status = CKYApplet_GetLifeCycleV2(conn, &lifeCycleV2, NULL);
    if (status != CKYSUCCESS) {
	if (status == CKYSCARDERR) {
	    disconnect();
	}
	return;
    }
    log->log("time connect: Get Personalization %d ms\n", OSTimeNow() - time);
    if (lifeCycleV2.lifeCycle == CKY_APPLICATION_PERSONALIZED )
    {
        state |= APPLET_PERSONALIZED;
    }
    isVersion1Key = (lifeCycleV2.protocolMajorVersion == 1);
    needLogin = (lifeCycleV2.pinCount != 0);
    tokenFWVersion.major = lifeCycleV2.protocolMajorVersion;
    tokenFWVersion.minor = lifeCycleV2.protocolMinorVersion;
    return;
coolkey_loser:
    log->log("CoolKey Select failed 0x%x\n", status);
    status = getCACAid();
    if (status != CKYSUCCESS) {
	goto cac_loser;
    }
    state |= CAC_CARD | APPLET_SELECTABLE | APPLET_PERSONALIZED;
    /* skip the read of the cuid. We really don't need it and,
     * the only way to get it from the cac is to reset it.
     * other apps may be running now, so resetting the cac is a bit
     * unfriendly */
    isVersion1Key = 0;
    needLogin = 1;
    mCoolkey = 0;
    mCACLocalLogin = false;
    return;
cac_loser:
    log->log("CAC Select failed 0x%x\n", status);
    if (status == CKYSCARDERR) {
	log->log("Card Failure 0x%x\n",
			CKYCardConnection_GetLastError(conn));
	disconnect();
    }
}
    
bool
Slot::cardStateMayHaveChanged()
{
    CKYStatus status;

log->log("calling IsConnected\n");
    if( !CKYCardConnection_IsConnected(conn) ) {
        return true;
    }
log->log("IsConnected returned false\n");
    
    // If the card has been removed or reset, this call will fail.
    unsigned long cardState;
    CKYBuffer aid;
    CKYBuffer_InitEmpty(&aid);
    status = CKYCardConnection_GetStatus(conn, &cardState, &aid);
    CKYBuffer_FreeData(&aid);
    if( status != CKYSUCCESS ) {
        disconnect();
        return true;
    }
    return false;
}

void
Slot::invalidateLogin(bool hard)
{
    if (isVersion1Key) {
	if (hard) {
	    reverify = false; /* no need to revalidate in the future,
	                       * we're clearing the nonce now */
	    nonceValid = false;
	    CKYBuffer_Zero(&nonce);
	    CKYBuffer_Resize(&nonce,8);
	} else {
	    reverify = true;
	}
    } else {
	loggedIn = false;
	pinCache.invalidate();
	if (hard) {
	    pinCache.clearPin();
	}
    }
}

void
Slot::disconnect()
{
    CKYCardConnection_Disconnect(conn);
    state = UNKNOWN;
    closeAllSessions();
    invalidateLogin(false);
}

CKYStatus
Slot::getCACAid()
{
    CKYBuffer tBuf;
    CKYBuffer vBuf;
    CKYSize tlen, vlen;
    CKYOffset toffset, voffset;
    int certSlot = 0;
    int i,length = 0;
    CKYStatus status;

    CKYBuffer_InitEmpty(&tBuf);
    CKYBuffer_InitEmpty(&vBuf);

    /* clear out the card AID's */
    for (i=0; i < MAX_CERT_SLOTS; i++) {
	CKYBuffer_Resize(&cardAID[i],0);
    }

    status = CACApplet_SelectCCC(conn,NULL);
    if (status != CKYSUCCESS) {
	/* are we an old CAC */
	status = CACApplet_SelectPKI(conn, &cardAID[0], 0, NULL);
	if (status != CKYSUCCESS) {
	   /* no, just fail */
	   return status;
	}
	/* yes, fill in the old applets */
	mOldCAC = true;
	for (i=1; i< MAX_CERT_SLOTS; i++) {
	    CACApplet_SelectPKI(conn, &cardAID[i], i, NULL);
	}
	return CKYSUCCESS;
    }
    /* definately not an old CAC */
    mOldCAC = false;

    /* read the TLV */
    status = CACApplet_ReadFile(conn, CAC_TAG_FILE, &tBuf, NULL);
    if (status != CKYSUCCESS) {
	goto done;
    }
    status = CACApplet_ReadFile(conn, CAC_VALUE_FILE, &vBuf, NULL);
    if (status != CKYSUCCESS) {
	goto done;
    }
    tlen = CKYBuffer_Size(&tBuf);
    vlen = CKYBuffer_Size(&vBuf);

    for(toffset = 2, voffset=2; 
	certSlot < MAX_CERT_SLOTS && toffset < tlen && voffset < vlen ; 
		voffset += length) {

	CKYByte tag = CKYBuffer_GetChar(&tBuf, toffset);
	length = CKYBuffer_GetChar(&tBuf, toffset+1);
	toffset += 2;
	if (length == 0xff) {
	    length = CKYBuffer_GetShortLE(&tBuf, toffset);
	    toffset +=2;
	}
	if (tag != CAC_TAG_CARDURL) {
	    continue;
	}
	/* CARDURL tags must be at least 10 bytes long */
	if (length < 10) {
	    continue;
	}
	/* check the app type, should be TLV_APP_PKI */
	if (CKYBuffer_GetChar(&vBuf, voffset+5) != CAC_TLV_APP_PKI) {
	    continue;
	}
	status = CKYBuffer_AppendBuffer(&cardAID[certSlot], &vBuf, voffset, 5);
	if (status != CKYSUCCESS) {
	    goto done;
	}
	status = CKYBuffer_AppendBuffer(&cardAID[certSlot], &vBuf, 
								voffset+8, 2);
	if (status != CKYSUCCESS) {
	    goto done;
	}
	cardEF[certSlot] = CKYBuffer_GetShortLE(&vBuf, voffset+6);

	certSlot++;
    }
    status = CKYSUCCESS;
    if (certSlot == 0) {
	status = CKYAPDUFAIL; /* probably neeed a beter error code */
    }

done:
    CKYBuffer_FreeData(&tBuf);
    CKYBuffer_FreeData(&vBuf);
    return status;
}

void
Slot::refreshTokenState()
{
    if( cardStateMayHaveChanged() ) {
        log->log("card changed\n");
	invalidateLogin(true);
        closeAllSessions();
	unloadObjects();
        connectToToken();

        if( state & APPLET_PERSONALIZED ) {
            try {
                loadObjects();
            } catch(PKCS11Exception&) {
                log->log("refreshTokenState: Failed to load objects.\n");
                unloadObjects();
            }
        } else if (state & APPLET_SELECTABLE) {
	    initEmpty();
	}

    }
}

bool
Slot::isTokenPresent()
{
    refreshTokenState();
    log->log("isTokenPresent, card state is 0x%x\n", state);
    return (state & APPLET_SELECTABLE) != 0;
}

CK_SESSION_HANDLE
makeSessionHandle(CK_SLOT_ID slotID, SessionHandleSuffix suffix)
{
    assert( (slotID & 0x000000ff) == slotID );
    return (slotID << 24) | suffix;
}

void
SlotList::decomposeSessionHandle(CK_SESSION_HANDLE hSession, CK_SLOT_ID& slotID,
    SessionHandleSuffix& suffix) const
{
    slotID = hSession >> 24;
    suffix = SessionHandleSuffix(hSession);
    try {
        validateSlotID(slotID);
    } catch(PKCS11Exception&) {
        log->log("Invalid slotID %d pulled from session handle 0x%08x\n",
            slotID, hSession);
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
}

void
SlotList::openSession(Session::Type type, CK_SLOT_ID slotID,
    CK_SESSION_HANDLE_PTR phSession)
{
    validateSlotID(slotID);

    SessionHandleSuffix suffix = 
        slots[slotIDToIndex(slotID)]->openSession(type);

    *phSession = makeSessionHandle(slotID, suffix);
}

void
SlotList::closeSession(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->closeSession(suffix);
}
    

SessionHandleSuffix
Slot::openSession(Session::Type type)
{
    ensureTokenPresent();
    return generateNewSession(type);
}

class SessionHandleSuffixMatch {
  private:
    SessionHandleSuffix suffix;
  public:
    explicit SessionHandleSuffixMatch(SessionHandleSuffix s) : suffix(s) { }
    bool operator()(const Session& session) {
        return session.getHandleSuffix() == suffix;
    }
};

bool
Slot::isValidSession(SessionHandleSuffix handleSuffix) const
{
    SessionConstIter iter;
    iter = findConstSession(handleSuffix);
    return (iter != sessions.end());
}

void
Slot::closeSession(SessionHandleSuffix handleSuffix)
{
    refreshTokenState();

    SessionIter iter;
    iter = findSession(handleSuffix);
    if( iter == sessions.end() )  {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID,
            "Invalid session handle suffix 0x%08x passed to closeSession\n",
                (unsigned long)handleSuffix);
    } else {
        log->log("Closed session 0x%08x\n", (unsigned long)handleSuffix);
        sessions.erase(iter);
    }
}

CK_RV
Slot::getSlotInfo(CK_SLOT_INFO_PTR pSlotInfo)
{
    static CK_VERSION firmwareVersion = {0,0};

    if( pSlotInfo == NULL ) {
        throw PKCS11Exception(CKR_ARGUMENTS_BAD);
    }
    pSlotInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    /*pSlotInfo->flags = CKF_REMOVABLE_DEVICE; */
    if( isTokenPresent() )
        pSlotInfo->flags |= CKF_TOKEN_PRESENT;
    memset(pSlotInfo->slotDescription, ' ', 64);
    memcpy(pSlotInfo->slotDescription, readerName,
        MIN(64, strlen(readerName)) );
    memset(pSlotInfo->manufacturerID, ' ', 32);
    memcpy(pSlotInfo->manufacturerID, manufacturer,
        MIN(32, strlen(manufacturer)) );
    pSlotInfo->hardwareVersion = hwVersion;
    pSlotInfo->firmwareVersion = firmwareVersion;

    return CKR_OK;
}

inline unsigned char 
hex(unsigned long digit) 
{
    return (digit > 9 )? (char)(digit+'a'-10) : (char)(digit+'0');
}

void
Slot::makeCUIDString(char *serialNumber, int maxSize,
						 const unsigned char *cuids)
{
    signed int i; // must be signed or for loop won't exit! 
    char *cp;

    memset(serialNumber, ' ', maxSize);
    // CUID is an 8 digit hex number with leading zeros.
    // we count down from 8 stripping hex digits. If there is not
    // enough space, we truncate the top digits 
    unsigned long cuid = 
	((unsigned long) cuids[6]) << 24 |
	((unsigned long) cuids[7]) << 16 |
	((unsigned long) cuids[8]) <<  8 |
		((unsigned long) cuids[9]) ;

    for (i = MIN(maxSize,8)-1, cp= serialNumber; i >= 0; 
						cp++, i--) {
	unsigned long digit = cuid >> (i*4);
	// if we truncated the beginning. show that with a '*' 
	*cp = (digit > 0xf) ? '*' : hex(digit);
	cuid -=  digit << (i*4);
    }
}


void
Slot::makeSerialString(char *serialNumber, int maxSize,
						 const unsigned char *cuid)
{
    memset(serialNumber, ' ', maxSize);

    // otherwise we use the eepromSerialNumber as a hex value 
    if (cuid) {
         makeCUIDString(serialNumber, maxSize, cuid);
    }
    return;
}

void
Slot::makeLabelString(char *label, int maxSize, const unsigned char *cuid)
{
    int personLen;
    memset(label, ' ', maxSize);
    if (fullTokenName) {
	personLen = strlen(personName);
	memcpy(label, personName, MIN(personLen, maxSize));
        // UTF8 Truncate fixup! don't drop halfway through a UTF8 character 
	return;
    }
    
// 
// Legacy tokens only 'speak' english.
//
#define COOLKEY "CoolKey"
#define POSSESSION " for "
    if (!personName || personName[0] == '\0' ) {
	const int coolKeySize = sizeof(COOLKEY) ;
	memcpy(label, COOLKEY, coolKeySize-1);
	makeSerialString(&label[coolKeySize], maxSize-coolKeySize, cuid);
	return;
    }
    const int prefixSize = sizeof (COOLKEY POSSESSION )-1;
    memcpy(label, COOLKEY POSSESSION, prefixSize);
    personLen = strlen(personName);
    memcpy(&label[prefixSize], personName, 
				MIN(personLen, maxSize-prefixSize));

}

void
Slot::makeModelString(char *model, int maxSize, const unsigned char *cuid)
{
    char *cp = model;
    memset(model, ' ', maxSize);
    assert(maxSize >= 8);

    if (!cuid) {
	return;
    }

    *cp++ = hex(cuid[2] >> 4);
    *cp++ = hex(cuid[2] & 0xf);
    *cp++ = hex(cuid[3] >> 4);
    *cp++ = hex(cuid[3] & 0xf);
    *cp++ = hex(cuid[4] >> 4);
    *cp++ = hex(cuid[4] & 0xf);
    *cp++ = hex(cuid[5] >> 4);
    *cp++ = hex(cuid[5] & 0xf);
    makeCUIDString(&model[8],maxSize -8, cuid);

    return;
}

struct _manList {
     unsigned short type;
     const char *string;
};

static const struct _manList  manList[] = {
        { 0x4090, "Axalto" },
        { 0x2050, "Oberthur" },
        { 0x4780, "RSA" }
};

static int manListSize = sizeof(manList)/sizeof(manList[0]);

void
Slot::makeManufacturerString(char *man, int maxSize, const unsigned char *cuid)
{
    char *cp = man;
    memset(man, ' ', maxSize);

    if (!cuid) {
	return;
    }
    unsigned short fabricator = ((unsigned short)cuid[0]) << 8 | cuid[1];

    assert(maxSize >=4 );

     /* first give the raw manufacture ID for CUID calculations */
    *cp++ = hex(cuid[0] >> 4);
    *cp++ = hex(cuid[0] & 0xf);
    *cp++ = hex(cuid[1] >> 4);
    *cp++ = hex(cuid[1] & 0xf);
    cp++; /* leave a space */


    for (int i=0; i < manListSize; i++) {
	if (fabricator == manList[i].type) {
	    int len = strlen(manList[i].string);
	    memcpy(cp,manList[i].string, MIN(len,maxSize-5));
	    break;
	}
    }
    /* just leave the number bare if we don't recognize it */
}

CK_RV
Slot::getTokenInfo(CK_TOKEN_INFO_PTR pTokenInfo)
{
    if(pTokenInfo == NULL ) {
        throw PKCS11Exception(CKR_ARGUMENTS_BAD);
    }
    ensureTokenPresent();
    const unsigned char *cuid = CKYBuffer_Data(&mCUID);

    /// format the token string
    makeLabelString((char *)pTokenInfo->label, sizeof(pTokenInfo->label),cuid);
    makeSerialString((char *)pTokenInfo->serialNumber, 
				sizeof(pTokenInfo->serialNumber), cuid);
    makeModelString((char *)pTokenInfo->model, 
				sizeof(pTokenInfo->model), cuid);
    makeManufacturerString((char *)pTokenInfo->manufacturerID, 
				sizeof(pTokenInfo->manufacturerID), cuid);

    pTokenInfo->flags = CKF_WRITE_PROTECTED;
    if (state & APPLET_PERSONALIZED) {
	pTokenInfo->flags |=  CKF_TOKEN_INITIALIZED;
	if (needLogin) {
	    pTokenInfo->flags |= CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
	}
    }
    pTokenInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pTokenInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pTokenInfo->ulMaxRwSessionCount = 0;
    pTokenInfo->ulMaxPinLen = 32;
    pTokenInfo->ulMinPinLen = 0;
    pTokenInfo->ulTotalPublicMemory = publicTotal;
    pTokenInfo->ulFreePublicMemory = publicFree;
    pTokenInfo->ulTotalPrivateMemory = CK_EFFECTIVELY_INFINITE;
    pTokenInfo->ulFreePrivateMemory = privateFree;
    pTokenInfo->hardwareVersion.major = cuid ? cuid[4] : 0;
    pTokenInfo->hardwareVersion.minor = cuid ? cuid[5] : 0;
    pTokenInfo->firmwareVersion = tokenFWVersion;


    return CKR_OK;
}

void
SlotList::validateSlotID(CK_SLOT_ID slotID) const
{
    if( slotID < 1 || slotID > numSlots ) {
        throw PKCS11Exception(CKR_SLOT_ID_INVALID);
    }
}

#define PKCS11_WAIT_LATENCY 500 /* 500 msec or 1/2 sec */
#define PKCS11_CARD_ERROR_LATENCY 300
void
SlotList::waitForSlotEvent(CK_FLAGS flag, CK_SLOT_ID_PTR slotp, CK_VOID_PTR res)
{
    unsigned long timeout = (flag ==CKF_DONT_BLOCK) ? 0 : PKCS11_WAIT_LATENCY;
    unsigned int i;
    bool found = FALSE;
    CKYStatus status;
    SCARD_READERSTATE *myReaderStates = NULL;
    unsigned int myNumReaders = 0;
#ifndef notdef
    do {
	readerListLock.getLock();
	try {
	    updateReaderList();
	} catch(PKCS11Exception&) {
	    readerListLock.releaseLock();
	    if (myReaderStates) {
		delete [] myReaderStates;
	    }
	    throw;
	}

	if (myNumReaders != numReaders) {
	    if (myReaderStates) {
		delete [] myReaderStates;
	    } 
	    myReaderStates = new SCARD_READERSTATE [numReaders];
	}
	memcpy(myReaderStates, readerStates, 
				sizeof(SCARD_READERSTATE)*numReaders);
	myNumReaders = numReaders;
	readerListLock.releaseLock();
	status = CKYCardContext_WaitForStatusChange(context,
				 myReaderStates, myNumReaders, timeout);
	if (status == CKYSUCCESS) {
	    for (i=0; i < myNumReaders; i++) {
		SCARD_READERSTATE *rsp = &myReaderStates[i];
	        unsigned long eventState = CKYReader_GetEventState(rsp);
		if (eventState & SCARD_STATE_CHANGED) {
		    readerListLock.getLock();
		    CKYReader_SetKnownState(&readerStates[i], eventState & ~SCARD_STATE_CHANGED);
		    readerListLock.releaseLock();
		    *slotp = slotIndexToID(i);
		    found = TRUE;
		    break;
		}
	    }
	}

        if (found || (flag == CKF_DONT_BLOCK) || shuttingDown) {
            break;
        }

        #ifndef WIN32
        if (status != CKYSUCCESS) {

            if ( (CKYCardContext_GetLastError(context) ==
                                        SCARD_E_READER_UNAVAILABLE) ||
                (CKYCardContext_GetLastError(context) == SCARD_E_TIMEOUT))
            {
                OSSleep(timeout*PKCS11_CARD_ERROR_LATENCY);
            }


        }
        #endif
    } while ((status == CKYSUCCESS) ||
       (CKYCardContext_GetLastError(context) == SCARD_E_TIMEOUT) ||
       (CKYCardContext_GetLastError(context) == SCARD_E_READER_UNAVAILABLE) ||
       (CKYCardContext_GetLastError(context) == SCARD_E_NO_SERVICE) ||
       (CKYCardContext_GetLastError(context) == SCARD_E_SERVICE_STOPPED) );
#else
    do {
	OSSleep(100);
    } while ((flag != CKF_DONT_BLOCK) && !shuttingDown);
#endif

    if (myReaderStates) {
	delete [] myReaderStates;
    }

    if (!found) {
	throw PKCS11Exception(CKR_NO_EVENT);
    }
    return;
}

void
Slot::handleConnectionError()
{
    long error = CKYCardConnection_GetLastError(conn);

    log->log("Connection Error = 0x%x\n", error);

    // Force a reconnect after a token operation fails. The most
    // common reason for it to fail is that it has been removed, but
    // it doesn't hurt to do it in other cases either (such as a reset).
    disconnect();

    // Convert the PCSC error to a PKCS #11 error, and throw the exception.
    CK_RV ckrv;
    switch( error ) {
      case SCARD_E_NO_SMARTCARD:
      case SCARD_W_RESET_CARD:
      case SCARD_W_REMOVED_CARD:
        ckrv = CKR_DEVICE_REMOVED;
        break;
      default:
        ckrv = CKR_DEVICE_ERROR;
        break;
    }
    throw PKCS11Exception(ckrv);
}

list<ListObjectInfo>
Slot::getObjectList()
{
    list<ListObjectInfo> objInfoList;

    while(true) {
	CKYISOStatus result;
        ListObjectInfo info;
        CKYByte seq = objInfoList.size() == 0  ? CKY_LIST_RESET : CKY_LIST_NEXT;
	CKYStatus status=CKYApplet_ListObjects(conn, seq,  &info.obj, &result);
	if (status != CKYSUCCESS) {
	    // we failed because of a connection error
	    if (status == CKYSCARDERR) {
		handleConnectionError();
	    }
	    // we failed simply because we hit the end of the list
	    // (in which case we are done)
	    if ((result == CKYISO_SUCCESS)  || (result == CKYISO_SEQUENCE_END)) {
		break;
	    }
	    // we failed fror some other reason...
  	    throw PKCS11Exception(CKR_DEVICE_ERROR);
	}

        log->log("===Object\n");
        log->log("===id: 0x%04x\n", info.obj.objectID);
        log->log("===size: %d\n", info.obj.objectSize);
        log->log("===acl: 0x%02x,0x%02x,0x%02x\n", info.obj.readACL,
				info.obj.writeACL, info.obj.deleteACL);
        log->log("\n");

        objInfoList.push_back(info);
    }

    return objInfoList;
}

// Should already have a transaction
void
Slot::selectApplet()
{
    CKYStatus status;
    status = CKYApplet_SelectCoolKeyManager(conn, NULL);
    if ( status == CKYSCARDERR ) handleConnectionError();
    if ( status != CKYSUCCESS) {
        // could not select applet: this just means it's not there
        disconnect();
        throw PKCS11Exception(CKR_DEVICE_REMOVED);
    }
}

void
Slot::selectCACApplet(CKYByte instance)
{
    CKYStatus status;
    /* PIV containers and keys by instance */
    static const int container[] = {
	0x5fc105, 0x5fc10a, 0x5fc10b, 0x5fc101,
	0x5fc10d, 0x5fc10e, 0x5fc10f, 0x5fc110, 
	0x5fc111, 0x5fc112, 0x5fc113, 0x5fc114, 
	0x5fc115, 0x5fc116, 0x5fc117, 0x5fc118, 
	0x5fc119, 0x5fc11a, 0x5fc11b, 0x5fc11c, 
	0x5fc11d, 0x5fc11e, 0x5fc11f, 0x5fc120
    };
    static const int keyRef[] = {
	0x9a,     0x9c,     0x9d,     0x9e,
	0x82,     0x83,     0x84,     0x85,
	0x86,     0x87,     0x88,     0x89,
	0x8a,     0x8b,     0x8c,     0x8d,
	0x8e,     0x8f,     0x90,     0x91,
	0x92,     0x93,     0x94,     0x95
    };

    if (state & PIV_CARD) {
        status = PIVApplet_Select(conn, NULL);
	if (status == CKYSCARDERR) handleConnectionError();
	if (status != CKYSUCCESS) {
	    disconnect();
	    throw PKCS11Exception(CKR_DEVICE_REMOVED);
	}
	pivContainer = container[instance];
	pivKey = keyRef[instance];
	return;
    }
    CKYBuffer *aid = &cardAID[instance];

    if (CKYBuffer_Size(aid) == 0) {
        disconnect();
        throw PKCS11Exception(CKR_DEVICE_REMOVED);
	return;
    }
    
    status = CKYApplet_SelectFile(conn, aid, NULL);
    if ( status == CKYSCARDERR ) handleConnectionError();
    if ( status != CKYSUCCESS) {
        // could not select applet: this just means it's not there
        disconnect();
        throw PKCS11Exception(CKR_DEVICE_REMOVED);
    }
    if (mOldCAC) {
	return;
    }
    status = CACApplet_SelectFile(conn, cardEF[instance], NULL);
    if ( status == CKYSCARDERR ) handleConnectionError();
    if ( status != CKYSUCCESS) {
        disconnect();
        throw PKCS11Exception(CKR_DEVICE_REMOVED);
    }
}
// assume we are already in a transaction
void
Slot::readMuscleObject(CKYBuffer *data, unsigned long objectID, 
							unsigned int objSize)
{
    CKYStatus status;

    status = CKYApplet_ReadObjectFull(conn, objectID, 0, objSize,
		getNonce(), data, NULL);
    if (status == CKYSCARDERR) { 
        handleConnectionError();
    }
    if (status != CKYSUCCESS) {
        throw PKCS11Exception(CKR_DEVICE_ERROR);
    }
    return;
}


class DERCertObjIDMatch {
  private:
    unsigned short certnum;
    const Slot      &slot;
  public:
    DERCertObjIDMatch(unsigned short cn, const Slot &s) : 
		certnum(cn), slot(s) { }

    bool operator()(const ListObjectInfo& info) {
        return  (slot.getObjectClass(info.obj.objectID) == 'C') 
		&& ( slot.getObjectIndex(info.obj.objectID) == certnum );
    }
};

class ObjectHandleMatch {
  private:
    CK_OBJECT_HANDLE handle;
  public:
    ObjectHandleMatch(CK_OBJECT_HANDLE handle_) : handle(handle_) { }
    bool operator()(const PKCS11Object& obj) {
        return obj.getHandle() == handle;
    }
};

class KeyNumMatch {
  private:
    CKYByte keyNum;
    const Slot &slot;
  public:
    KeyNumMatch(CKYByte keyNum_, const Slot &s) : keyNum(keyNum_), slot(s) { }
    bool operator() (const PKCS11Object& obj) {
        unsigned long objID = obj.getMuscleObjID();
        return (slot.getObjectClass(objID) == 'k')
               && (slot.getObjectIndex(objID) == keyNum);
    }
};

class ObjectCertCKAIDMatch {
  private:
    CKYByte cka_id;
  public:
    ObjectCertCKAIDMatch(CKYByte cka_id_) : cka_id(cka_id_) {}
    bool operator()(const PKCS11Object& obj) {
	const CKYBuffer *id;
        const CKYBuffer *objClass;
	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	objClass = obj.getAttribute(CKA_CLASS);
        if (objClass == NULL || !CKYBuffer_DataIsEqual(objClass, 
				(CKYByte *)&certClass, sizeof(certClass))) {
	    return false;
        }
 	id = obj.getAttribute(CKA_ID);
        return (id != NULL && CKYBuffer_DataIsEqual(id,&cka_id, 1))
						 ? true : false;
    }
};

CK_OBJECT_HANDLE
Slot::generateUnusedObjectHandle()
{
    CK_OBJECT_HANDLE handle;
    ObjectConstIter iter;
    do {
        handle = ++objectHandleCounter;
        iter = find_if(tokenObjects.begin(), tokenObjects.end(),
            ObjectHandleMatch(handle));
    } while( handle == CK_INVALID_HANDLE || iter != tokenObjects.end() );
    return handle;
}

void
Slot::addKeyObject(list<PKCS11Object>& objectList, const ListObjectInfo& info,
    CK_OBJECT_HANDLE handle, bool isCombined)
{
    ObjectConstIter iter;
    Key keyObj(info.obj.objectID, &info.data, handle);
    CK_OBJECT_CLASS objClass = keyObj.getClass();
    const CKYBuffer *id;


    if (isCombined &&
	   ((objClass == CKO_PUBLIC_KEY) || (objClass == CKO_PRIVATE_KEY))) {
	id = keyObj.getAttribute(CKA_ID);
	if ((!id) || (CKYBuffer_Size(id) != 1)) {
	    throw PKCS11Exception(CKR_DEVICE_ERROR,
			"Missing or invalid CKA_ID value");
	}
	iter = find_if(objectList.begin(), objectList.end(),
			ObjectCertCKAIDMatch(CKYBuffer_GetChar(id,0)));
	if ( iter == objectList.end() ) {
            // We failed to find a cert with a matching CKA_ID. This
            // can happen if the cert is not present on the token, or
            // the der encoded cert stored on the token was corrupted.
	    throw PKCS11Exception(CKR_DEVICE_ERROR,
			"Failed to find cert with matching CKA_ID value");
	}
	keyObj.completeKey(*iter);
    }
    objectList.push_back(keyObj);

}

void
Slot::addObject(list<PKCS11Object>& objectList, const ListObjectInfo& info,
    CK_OBJECT_HANDLE handle)
{
    objectList.push_back(PKCS11Object(info.obj.objectID, &info.data, handle));
}

void
Slot::addCertObject(list<PKCS11Object>& objectList, 
    const ListObjectInfo& certAttrs,
    const CKYBuffer *derCert, CK_OBJECT_HANDLE handle)
{
    Cert certObj(certAttrs.obj.objectID, 
				&certAttrs.data, handle, derCert);
    if (personName == NULL) {
	personName = strdup(certObj.getLabel());
	fullTokenName = false;
    }

    objectList.push_back(certObj);
}
void
Slot::unloadObjects()
{
    tokenObjects.clear();
    free(personName);
    personName = NULL;
    fullTokenName = false;
}

#ifdef USE_SHMEM

// The shared memory segment is used to cache the raw token objects from
// the card so mupltiple instances do not need to read all the data in
// by themselves. It also allows us to recover data from a token on 
// reinsertion if that token is inserted into the same 'slot' as it was
// originally.
//
// There is one memory segment for each slot.
//
// The process that creates the shared memory segment will initialize the
// valid byte to '0'. Otherwise the Memory Segment must be accessed while 
// in a transaction for the connection to a reader that the memory segment 
// represents is held.
//
// If the memory segment is not valid, does not match the CUID of the 
// current token, or does not match the current data version, the current 
// process will read the object data out of the card  and into shared memory.
// Since access to the shared memory is protected by the interprocess 
// transaction lock on the reader, data consistancy is
// maintained.
//
// shared memory is layed out as follows:
//
// Header:
//  1 short  (version) shared mem layout version number (currrent 1,0)
//  1 short  (header size) size in bytes of the shared memory header
//  1 byte   (valid)  segment is valid or not (valid =1; not valid =0 )
//  1 byte   (reserved) (set to zero)
//  10 bytes (CUID)  Unique card identifier.
//  1 short  (reserved) (set to zero)
//  1 short  (data version) version number of the embeded data
//  1 short  (header offset) offset to the card's data header.
//  1 short  (data offset) offset to the uncompressed card data.
//  1 long   (header size) size in bytes of the card's data header.
//  1 long   (data size) size in bytes of the uncompressed data.
//  .
//  .
// DataHeader:
//  n bytes  DataHeader.
//  .
//  .
// Data:
//  n bytes   Data.
//
// All data in the shared memory header is stored in machine order, packing,
//  and size. Data in the DataHeader and Data sections are stored in applet 
//  byte order.
//
// Shared memory segments are fixed size (equal to the object memory size of
// the token). 
//

struct SlotSegmentHeader {
    unsigned short version;
    unsigned short headerSize;
    unsigned char  valid;
    unsigned char  reserved;
    unsigned char  cuid[10];
    unsigned short reserved2;
    unsigned short dataVersion;
    unsigned short dataHeaderOffset;
    unsigned short dataOffset;
    unsigned long  dataHeaderSize;
    unsigned long  dataSize;
    unsigned long  cert2Offset;
    unsigned long  cert2Size;
};

#define MAX_OBJECT_STORE_SIZE 15000
//
// previous development versions used a segment prefix of
// "coolkeypk11s"
//
#define SEGMENT_PREFIX "coolkeypk11s"
#define CAC_FAKE_CUID "CAC Certs"
SlotMemSegment::SlotMemSegment(const char *readerName): 
	segmentAddr(NULL),  segmentSize(0), segment(NULL)
{
   bool needInit;
   char *segName;

   segName = new char[strlen(readerName)+sizeof(SEGMENT_PREFIX)+1];
   if (!segName) {
	// just run without shared memory
	return;
    }
    sprintf(segName,SEGMENT_PREFIX"%s",readerName); 
    segment = SHMem::initSegment(segName, MAX_OBJECT_STORE_SIZE, needInit);
    delete [] segName;
    if (!segment) {
	// just run without shared memory
	return;
    }
    segmentAddr = segment->getSHMemAddr();
    assert(segmentAddr);
    // paranoia, shouldn't happen..
    if (!segmentAddr) {
	delete segment;
	segment = NULL;
	return;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    if (needInit) {
	segmentHeader->valid = 0;
    }
    segmentSize = segment->getSHMemSize();
}

SlotMemSegment::~SlotMemSegment()
{
    if (segment) {
	delete segment;
    }
}

bool
SlotMemSegment::CUIDIsEqual(const CKYBuffer *cuid) const
{
    if (!segment) {
	return false;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;

    return 
     CKYBuffer_DataIsEqual(cuid, (CKYByte *)segmentHeader->cuid, 
	sizeof(segmentHeader->cuid)) ? true : false;
}

void
SlotMemSegment::setCUID(const CKYBuffer *cuid)
{
    if (!segment) {
	return;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;

    if (CKYBuffer_Size(cuid) != sizeof(segmentHeader->cuid)) {
	// should throw and exception?
	return;
    }
    memcpy (segmentHeader->cuid, CKYBuffer_Data(cuid),
					sizeof(segmentHeader->cuid));
}

const unsigned char *
SlotMemSegment::getCUID() const
{
    if (!segment) {
	return NULL;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    return segmentHeader->cuid;
}

unsigned short
SlotMemSegment::getVersion() const
{
    if (!segment) {
	return 0;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    return segmentHeader->version;
}

unsigned short
SlotMemSegment::getDataVersion() const
{
    if (!segment) {
	return 0;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    return segmentHeader->dataVersion;
}

void
SlotMemSegment::setVersion(unsigned short version)
{
    if (!segment) {
	return;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    segmentHeader->version = version;
}


void
SlotMemSegment::setDataVersion(unsigned short version)
{
    if (!segment) {
	return;
    }

    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    segmentHeader->dataVersion = version;
}

bool
SlotMemSegment::isValid() const
{
    if (!segment) {
	return false;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    return segmentHeader->valid == 1;
}

void
SlotMemSegment::readHeader(CKYBuffer *dataHeader) const
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size = segmentHeader->dataHeaderSize;
    CKYByte *data = (CKYByte *) &segmentAddr[segmentHeader->dataHeaderOffset];
    CKYBuffer_Replace(dataHeader, 0, data, size);
}

void
SlotMemSegment::readData(CKYBuffer *objData) const
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size = segmentHeader->dataSize;
    CKYByte *data = (CKYByte *) &segmentAddr[segmentHeader->dataOffset];
    CKYBuffer_Replace(objData, 0, data, size);
}


void
SlotMemSegment::writeHeader(const CKYBuffer *dataHeader)
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size = CKYBuffer_Size(dataHeader);
    segmentHeader->headerSize = sizeof *segmentHeader;
    segmentHeader->dataHeaderSize = size;
    segmentHeader->dataHeaderOffset = sizeof *segmentHeader;
    segmentHeader->dataOffset = segmentHeader->dataHeaderOffset + size;
    CKYByte *data = (CKYByte *) &segmentAddr[segmentHeader->dataHeaderOffset];
    memcpy(data, CKYBuffer_Data(dataHeader), size);
}

void
SlotMemSegment::writeData(const CKYBuffer *objData)
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size = CKYBuffer_Size(objData);
    segmentHeader->dataSize = size;
    CKYByte *data = (CKYByte *) &segmentAddr[segmentHeader->dataOffset];
    memcpy(data, CKYBuffer_Data(objData), size);
}

void
SlotMemSegment::readCACCert(CKYBuffer *objData, CKYByte instance) const
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size;
    CKYByte *data;

    switch (instance) {
    case 0:
	data  = (CKYByte *) &segmentAddr[segmentHeader->dataHeaderOffset];
	size = segmentHeader->dataHeaderSize;
	break;
    case 1:
	data  = (CKYByte *) &segmentAddr[segmentHeader->dataOffset];
	size = segmentHeader->dataSize;
	break;
    case 2:
	data  = (CKYByte *) &segmentAddr[segmentHeader->cert2Offset];
	size = segmentHeader->cert2Size;
	break;
    default:
	CKYBuffer_Resize(objData, 0);
	return;
    }
    CKYBuffer_Replace(objData, 0, data, size);
}


void
SlotMemSegment::writeCACCert(const CKYBuffer *data, CKYByte instance)
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    int size = CKYBuffer_Size(data);
    CKYByte *shmData;
    switch (instance) {
    case 0:
	segmentHeader->headerSize = sizeof *segmentHeader;
	segmentHeader->dataHeaderOffset = sizeof *segmentHeader;
	segmentHeader->dataHeaderSize = size;
	segmentHeader->dataOffset = segmentHeader->dataHeaderOffset + size;
	segmentHeader->dataSize = 0;
	segmentHeader->cert2Offset = segmentHeader->dataOffset;
	segmentHeader->cert2Size = 0;
	shmData = (CKYByte *) &segmentAddr[segmentHeader->dataHeaderOffset];
	break;
    case 1:
	segmentHeader->dataSize = size;
	segmentHeader->cert2Offset = segmentHeader->dataOffset + size;
	segmentHeader->cert2Size = 0;
	shmData = (CKYByte *) &segmentAddr[segmentHeader->dataOffset];
	break;
    case 2:
	segmentHeader->cert2Size = size;
	shmData = (CKYByte *) &segmentAddr[segmentHeader->cert2Offset];
	break;
    default:
	return;
    }
    memcpy(shmData, CKYBuffer_Data(data), size);
}

void
SlotMemSegment::clearValid(CKYByte instance)
{

    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    switch (instance) {
    case 0:
	segmentHeader->headerSize = 0;
	segmentHeader->dataHeaderSize = 0;
	/* fall through */
    case 1:
	segmentHeader->dataSize = 0;
    }
    segmentHeader->valid = 0;
}

void
SlotMemSegment::setValid()
{
    if (!segment) {
	return;
    }
    SlotSegmentHeader *segmentHeader = (SlotSegmentHeader *)segmentAddr;
    segmentHeader->valid = 1;
}

#endif

void
Slot::initEmpty(void)
{
    // check the shared memory area first
    // shared memory is protected by our transaction call on the card
    //
    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS ) {
        handleConnectionError();
    }

    loadReaderObject();
    readCUID();
}

void
Slot::readCUID(void)
{
    // check the shared memory area first
    // shared memory is protected by our transaction call on the card
    //
    CKYStatus status;
    if (state & GOV_CARD) {
	status = CACApplet_SelectCardManager(conn, NULL);
    } else {
	status = CKYApplet_SelectCardManager(conn, NULL);
    }
    CKYBuffer_Resize(&mCUID, 0);
    if (status == CKYSCARDERR) {
	handleConnectionError();
    }
    status = CKYApplet_GetCUID(conn, &mCUID, NULL);
    if (status == CKYSCARDERR) {
	handleConnectionError();
    }
}

list<ListObjectInfo>
Slot::fetchSeparateObjects()
{
    int i;

    list<ListObjectInfo> objInfoList;
    std::list<ListObjectInfo>::iterator iter;

    OSTime time = OSTimeNow();
    readCUID();
    selectApplet();
    log->log(
     "time fetch separate: getting  cuid & applet select (again) %d ms\n",
							 OSTimeNow() - time);

#ifdef USE_SHMEM
    shmem.clearValid(0);
#endif

    //
    // get the list of objects on the muscle token
    //
    objInfoList = getObjectList();


    log->log("time fetch separate:  getObjectList %d ms\n",OSTimeNow() - time);
    //
    // get the content of each object
    //
    for (i=0, iter = objInfoList.begin(); iter != objInfoList.end(); 
								++iter, i++) {
	// check the ACL to make sure this will succeed.
	unsigned short readPerm = iter->obj.readACL;

	log->log("Object has read perm 0x%04x\n", readPerm);
	if ( (!isVersion1Key && ((readPerm & 0x2) == readPerm)) ||
 				(isVersion1Key && ((readPerm & 0x1))) ) {
	    readMuscleObject(&iter->data, iter->obj.objectID, 
						iter->obj.objectSize);
	    log->log("Object:\n");
	    log->dump(&iter->data);
	}
    }
    log->log("time fetch separate: readObjects %dms\n", OSTimeNow() - time);
    return objInfoList;
}

list<ListObjectInfo>
Slot::fetchCombinedObjects(const CKYBuffer *header)
{
    CKYBuffer objBuffer;
    CKYStatus status;

    list<ListObjectInfo> objInfoList;
    CKYBuffer_InitEmpty(&objBuffer);
    unsigned short compressedOffset = CKYBuffer_GetShort(
					header, OBJ_COMP_OFFSET_OFFSET);
    unsigned short compressedSize = CKYBuffer_GetShort(
					header, OBJ_COMP_SIZE_OFFSET);
    OSTime time = OSTimeNow();

#ifdef USE_SHMEM

    // check the shared memory area first
    // shared memory is protected by our transaction call on the card
    //
    CKYBuffer_Resize(&mCUID,0);
    CKYBuffer_AppendBuffer(&mCUID, header, OBJ_CUID_OFFSET, OBJ_CUID_SIZE);
    unsigned short dataVersion = CKYBuffer_GetShort(
					header, OBJ_OBJECT_VERSION_OFFSET);

    if (shmem.isValid() &&  shmem.CUIDIsEqual(&mCUID) && 
			shmem.getDataVersion() == dataVersion) {
	shmem.readData(&objBuffer);
    } else {
	shmem.clearValid(0);
	shmem.setCUID(&mCUID);
	shmem.setVersion(SHMEM_VERSION);
	shmem.setDataVersion(dataVersion);
	CKYBuffer dataHeader;
	CKYBuffer_InitFromBuffer(&dataHeader, header, 0, 
					(CKYSize) compressedOffset);

	shmem.writeHeader(&dataHeader);
	CKYBuffer_FreeData(&dataHeader);
	log->log("time fetch combined: play with shared memory %d ms\n",
		 OSTimeNow() - time);
#endif
	CKYBuffer_Reserve(&objBuffer, compressedSize);
	CKYSize headerSize = CKYBuffer_Size(header);
	CKYSize headerBytes = headerSize - compressedOffset;


	CKYBuffer_AppendBuffer(&objBuffer,header,compressedOffset,headerBytes);
	log->log("time fetch combined: "
		"headerbytes = %d compressedOffset = %d compressedSize = %d\n",
				headerBytes, compressedOffset, compressedSize);
	status = CKYApplet_ReadObjectFull(conn, COMBINED_ID, 
		headerSize, compressedSize - headerBytes, getNonce(), 
						&objBuffer, NULL);
	log->log("time fetch combined: read status = %d objectBuffSize = %d\n",
			 status, CKYBuffer_Size(&objBuffer));
	if (status == CKYSCARDERR) { 
	    CKYBuffer_FreeData(&objBuffer);
	    handleConnectionError();
	}
	log->log("time fetch combined: "
		"Read Object Data %d  ms (object size = %d bytes)\n",
		 OSTimeNow() - time, compressedSize);
	if (CKYBuffer_GetShort(header, OBJ_COMP_TYPE_OFFSET) == COMP_ZLIB) {
	    CKYBuffer compBuffer;
	    CKYSize guessFinalSize = CKYBuffer_Size(&objBuffer);
	    CKYSize objSize = 0;
	    int zret = Z_MEM_ERROR;

	    CKYBuffer_InitFromCopy(&compBuffer,&objBuffer);
	    do {
		guessFinalSize *= 2;
		status = CKYBuffer_Resize(&objBuffer, guessFinalSize);
		if (status != CKYSUCCESS) {
		    break;
		}
		objSize = guessFinalSize;
		zret = uncompress((Bytef *)CKYBuffer_Data(&objBuffer),&objSize,
			CKYBuffer_Data(&compBuffer), CKYBuffer_Size(&compBuffer));
	    } while (zret == Z_BUF_ERROR);
	    log->log("time fetch combined: "
		"uncompress objects %d  ms (object size = %d bytes)\n",
		 OSTimeNow() - time, objSize);

	    CKYBuffer_FreeData(&compBuffer);
	    if (zret != Z_OK) {
		CKYBuffer_FreeData(&objBuffer);
		throw PKCS11Exception(CKR_DEVICE_ERROR, 
				"Corrupted compressed object Data");
	    }
	    CKYBuffer_Resize(&objBuffer,objSize);
 	}
	
	// uncompress...
#ifdef USE_SHMEM
	shmem.writeData(&objBuffer);
	shmem.setDataVersion(dataVersion);
	shmem.setValid();
    }
#endif

     //
     // now pull apart the objects
     //
    unsigned short offset = 
		CKYBuffer_GetShort(&objBuffer, OBJ_OBJECT_OFFSET_OFFSET);
    unsigned short objectCount = CKYBuffer_GetShort(
					&objBuffer, OBJ_OBJECT_COUNT_OFFSET);
    int tokenNameSize = CKYBuffer_GetChar(&objBuffer,OBJ_TOKENNAME_SIZE_OFFSET);
    int i;
    CKYSize size = CKYBuffer_Size(&objBuffer);

    if (offset < tokenNameSize+OBJ_TOKENNAME_OFFSET) {
	CKYBuffer_FreeData(&objBuffer);
	throw PKCS11Exception(CKR_DEVICE_ERROR,
			"Tokenname/object Data overlap");
    }
    if (personName) {
	free(personName);
    }
    personName = (char *)malloc(tokenNameSize+1);
    memcpy(personName,CKYBuffer_Data(&objBuffer)+OBJ_TOKENNAME_OFFSET,
								tokenNameSize);
    personName[tokenNameSize] = 0;
    fullTokenName = true;

    for (i=0; i < objectCount && offset < size; i++) {
	ListObjectInfo info;
	unsigned long objectID = CKYBuffer_GetLong(&objBuffer, offset);
	unsigned long attrsCount= CKYBuffer_GetShort(&objBuffer, offset+8);
	unsigned long start = offset;
	unsigned int j;

	info.obj.objectID = objectID;
	offset +=10;

	/* get the length of the attribute block */
	for (j=0; j < attrsCount; j++) {
	    CKYByte attributeDataType=CKYBuffer_GetChar(&objBuffer, offset +4);

	    offset += 5;

	    switch (attributeDataType) {
	    case DATATYPE_STRING:
                offset += CKYBuffer_GetShort(&objBuffer, offset) + 2;
                break;
            case DATATYPE_BOOL_FALSE:
	    case DATATYPE_BOOL_TRUE:
                break;
	    case DATATYPE_INTEGER:
                offset += 4;
                break;
            }
	}
	if (offset > size) {
	    CKYBuffer_FreeData(&objBuffer);
	    throw PKCS11Exception(CKR_DEVICE_ERROR,
			"Inconsistant combined object data");
	}
	CKYSize objSize = offset - start;
	CKYBuffer_Reserve(&info.data, objSize +1);
	// tell the object parsing code that this is a new, compact type
	CKYBuffer_AppendChar(&info.data,1);
	// copy the object
	CKYBuffer_AppendBuffer(&info.data, &objBuffer, start, objSize);
        objInfoList.push_back(info);
    }
    CKYBuffer_FreeData(&objBuffer);
    log->log("fetch combined: format objects %d ms\n", OSTimeNow() - time);
    return objInfoList;
}

typedef enum {
	BER_UNWRAP,
	BER_NEXT
} BERop;

static CKYStatus
berProcess(CKYBuffer *buf, int matchTag, CKYBuffer *target, BERop type)
{
    unsigned char tag;
    unsigned int used_length= 0;
    unsigned int data_length;

    tag = CKYBuffer_GetChar(buf,used_length++);

    /* blow out when we come to the end */
    if (matchTag && tag != matchTag) {
        return CKYLIBFAIL;
    }

    data_length = CKYBuffer_GetChar(buf,used_length++);

    if (data_length & 0x80) {
        int  len_count = data_length & 0x7f;

        data_length = 0;

        while (len_count-- > 0) {
            data_length = (data_length << 8) | 
				CKYBuffer_GetChar(buf,used_length++);
        }
    }

    if (data_length > (CKYBuffer_Size(buf)-used_length) ) {
        return CKYLIBFAIL;
    }

    if (type == BER_UNWRAP) {
        return CKYBuffer_AppendBuffer(target, buf, used_length, data_length);
    }
    return CKYBuffer_AppendBuffer(target, buf, used_length+data_length,
		CKYBuffer_Size(buf)-(used_length+data_length));
}


CKYStatus
Slot::readCACCertificateFirst(CKYBuffer *cert, CKYSize *nextSize, 
			      bool throwException)
{
    CKYStatus status;
    CKYISOStatus apduRC;
    *nextSize = 0;

    if (state & PIV_CARD) {
	CKYBuffer pivData;
	CKYBuffer certInfo;

	CKYBuffer_InitEmpty(&pivData);
	CKYBuffer_InitEmpty(&certInfo);
	CKYBuffer_Resize(cert, 0);
	status = PIVApplet_GetCertificate(conn, cert, pivContainer, &apduRC);
	if (throwException && (status != CKYSUCCESS)) {
	    handleConnectionError();
	}
	/* actually, on success, we need to parse the certificate and find the
	 * propper tag */
	if (status == CKYSUCCESS) {
	    status = berProcess(cert, 0x53, &pivData, BER_UNWRAP);
	    CKYBuffer_Resize(cert, 0);
	    CKYBuffer_AppendChar(cert,0);
	    do {
		CKYByte tag = CKYBuffer_GetChar(&pivData,0);
		if (tag == CAC_TAG_CERTIFICATE) {
		    status = berProcess(&pivData, CAC_TAG_CERTIFICATE, 
					cert, BER_UNWRAP);
		}
		if (tag == CAC_TAG_CERTINFO) {
		    CKYBuffer_Resize(&certInfo, 0);
		    status = berProcess(&pivData, CAC_TAG_CERTINFO, 
					&certInfo, BER_UNWRAP);
		    if (CKYBuffer_Size(&certInfo) == 1) {
			CKYBuffer_SetChar(cert,0,
					CKYBuffer_GetChar(&certInfo,0));
		    }
		}
		if (status == CKYSUCCESS) {
		    CKYBuffer_Resize(&certInfo, 0);
		    status = berProcess(&pivData, 0, &certInfo, BER_NEXT);
		    if (status == CKYSUCCESS) {
			CKYBuffer_Resize(&pivData,0);
			status = CKYBuffer_AppendCopy(&pivData,&certInfo);
		    }
		}
	    } while ((status == CKYSUCCESS) && (CKYBuffer_Size(&pivData) != 0));
	    CKYBuffer_FreeData(&pivData);
	    CKYBuffer_FreeData(&certInfo);
	}
	
	return status;
    }

    if (mOldCAC) {
	/* get the first 100 bytes of the cert */
	status = CACApplet_GetCertificateFirst(conn, cert, nextSize, &apduRC);
	if (throwException && (status != CKYSUCCESS)) {
	    handleConnectionError();
	}
	return status;
    }

    CKYBuffer tBuf;
    CKYBuffer vBuf;
    CKYSize tlen, vlen;
    CKYOffset toffset, voffset;
    int length = 0;

    CKYBuffer_InitEmpty(&tBuf);
    CKYBuffer_InitEmpty(&vBuf);
    CKYBuffer_Resize(cert, 0);
    CKYBuffer_AppendChar(cert,0);

    /* handle the new CAC card read */
    /* read the TLV */
    status = CACApplet_ReadFile(conn, CAC_TAG_FILE, &tBuf, NULL);
    if (status != CKYSUCCESS) {
	goto done;
    }
    status = CACApplet_ReadFile(conn, CAC_VALUE_FILE, &vBuf, NULL);
    if (status != CKYSUCCESS) {
	goto done;
    }
    tlen = CKYBuffer_Size(&tBuf);
    vlen = CKYBuffer_Size(&vBuf);

    /* look for the Cert out of the TLV */
    for(toffset = 2, voffset=2; toffset < tlen && voffset < vlen ; 
		voffset += length) {

	CKYByte tag = CKYBuffer_GetChar(&tBuf, toffset);
	length = CKYBuffer_GetChar(&tBuf, toffset+1);
	toffset += 2;
	if (length == 0xff) {
	    length = CKYBuffer_GetShortLE(&tBuf, toffset);
	    toffset +=2;
	}
	if (tag == CAC_TAG_CERTIFICATE) {
	    CKYBuffer_AppendBuffer(cert, &vBuf, voffset, length);
	}
	if (tag == CAC_TAG_CERTINFO) {
	    CKYBuffer_SetChar(cert,0,CKYBuffer_GetChar(&vBuf,voffset));
	}
    }
    status = CKYSUCCESS;

done:
    CKYBuffer_FreeData(&tBuf);
    CKYBuffer_FreeData(&vBuf);
    return status;
}


const static unsigned long crc_table[] = {
0x00000000,0x77073096,0xee0e612c,0x990951ba,
0x076dc419,0x706af48f,0xe963a535,0x9e6495a3,
0x0edb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,
0x09b64c2b,0x7eb17cbd,0xe7b82d07,0x90bf1d91,
0x1db71064,0x6ab020f2,0xf3b97148,0x84be41de,
0x1adad47d,0x6ddde4eb,0xf4d4b551,0x83d385c7,
0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,
0x14015c4f,0x63066cd9,0xfa0f3d63,0x8d080df5,
0x3b6e20c8,0x4c69105e,0xd56041e4,0xa2677172,
0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,
0x35b5a8fa,0x42b2986c,0xdbbbc9d6,0xacbcf940,
0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,
0x26d930ac,0x51de003a,0xc8d75180,0xbfd06116,
0x21b4f4b5,0x56b3c423,0xcfba9599,0xb8bda50f,
0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,
0x2f6f7c87,0x58684c11,0xc1611dab,0xb6662d3d,
0x76dc4190,0x01db7106,0x98d220bc,0xefd5102a,
0x71b18589,0x06b6b51f,0x9fbfe4a5,0xe8b8d433,
0x7807c9a2,0x0f00f934,0x9609a88e,0xe10e9818,
0x7f6a0dbb,0x086d3d2d,0x91646c97,0xe6635c01,
0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,
0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,
0x65b0d9c6,0x12b7e950,0x8bbeb8ea,0xfcb9887c,
0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,
0x4db26158,0x3ab551ce,0xa3bc0074,0xd4bb30e2,
0x4adfa541,0x3dd895d7,0xa4d1c46d,0xd3d6f4fb,
0x4369e96a,0x346ed9fc,0xad678846,0xda60b8d0,
0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,
0x5005713c,0x270241aa,0xbe0b1010,0xc90c2086,
0x5768b525,0x206f85b3,0xb966d409,0xce61e49f,
0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,
0x59b33d17,0x2eb40d81,0xb7bd5c3b,0xc0ba6cad,
0xedb88320,0x9abfb3b6,0x03b6e20c,0x74b1d29a,
0xead54739,0x9dd277af,0x04db2615,0x73dc1683,
0xe3630b12,0x94643b84,0x0d6d6a3e,0x7a6a5aa8,
0xe40ecf0b,0x9309ff9d,0x0a00ae27,0x7d079eb1,
0xf00f9344,0x8708a3d2,0x1e01f268,0x6906c2fe,
0xf762575d,0x806567cb,0x196c3671,0x6e6b06e7,
0xfed41b76,0x89d32be0,0x10da7a5a,0x67dd4acc,
0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,
0xd6d6a3e8,0xa1d1937e,0x38d8c2c4,0x4fdff252,
0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,
0xdf60efc3,0xa867df55,0x316e8eef,0x4669be79,
0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,
0xcc0c7795,0xbb0b4703,0x220216b9,0x5505262f,
0xc5ba3bbe,0xb2bd0b28,0x2bb45a92,0x5cb36a04,
0xc2d7ffa7,0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,
0x9b64c2b0,0xec63f226,0x756aa39c,0x026d930a,
0x9c0906a9,0xeb0e363f,0x72076785,0x05005713,
0x95bf4a82,0xe2b87a14,0x7bb12bae,0x0cb61b38,
0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0x0bdbdf21,
0x86d3d2d4,0xf1d4e242,0x68ddb3f8,0x1fda836e,
0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,
0x88085ae6,0xff0f6a70,0x66063bca,0x11010b5c,
0x8f659eff,0xf862ae69,0x616bffd3,0x166ccf45,
0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,
0xa7672661,0xd06016f7,0x4969474d,0x3e6e77db,
0xaed16a4a,0xd9d65adc,0x40df0b66,0x37d83bf0,
0xa9bcae53,0xdebb9ec5,0x47b2cf7f,0x30b5ffe9,
0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,
0xbad03605,0xcdd70693,0x54de5729,0x23d967bf,
0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,
0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d
};

static unsigned long 
calc_crc32(const unsigned char *buf, int len)
{
    unsigned long crc = 0xffffffff;
    int i;

    for (i=0; i < len; i++) {
	unsigned char crc_low = crc & 0xff;
	unsigned long crc_high = crc >> 8;
	crc = crc_table[crc_low ^ buf[i]] ^ crc_high;
    }
    return crc ^ 0xffffffff;
}

/*
 * decompress, handles both gzip and zlib trailers
 * it also automatically allocates the output buffer and expands it as 
 * necessary.
 */
static int 
decompress(CKYBuffer *out, 
			CKYBuffer *in, CKYOffset offset, CKYSize len)
{
    int zret;
    CKYStatus status;
    z_stream stream;
    int chunk = len *2;
    int outlen = 0;
    

    /* allocate inflate state */
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;
    zret = inflateInit(&stream);
    if (zret != Z_OK)
        return zret;

    status = CKYBuffer_Reserve(out, outlen);
    if (status != CKYSUCCESS) {
	return Z_MEM_ERROR;
    }

    stream.avail_in = len;
    stream.next_in =  (Bytef *)(CKYBuffer_Data(in) + offset);

    do {
	CKYBuffer_Resize(out, outlen + chunk);
 	stream.avail_out = chunk;

	stream.next_out = (Bytef *)CKYBuffer_Data(out)+ outlen;

	zret= inflate(&stream, Z_NO_FLUSH);

	/* we need the length early so it can be used in error processing */
	outlen += chunk - stream.avail_out;

	/* proccess the error codes */
	switch (zret) {
	case Z_DATA_ERROR:
	    /* a DATA error can occur on either corrupted data, or on gzip.
	     * data. This is because gzip uses CRC32 and zlib used ADLER32
	     * checksums. We need to check to see if this failure is do to
	     * a gzip header. */
	    /* 1) a gzip header includes 4 extra bytes containing the length
	     * of the gziped data. This means there must be 4 more bytes
	     * in our input buffer that have not been processed */
	    if (stream.avail_in != 4) {
		break; /* not a gzip header */
	    }
	    /* The last 4 bytes of a gzip header include the uncompressed length
	     * modulo 2^32. Make sure the actual uncompressed length matches
	     * the header. */
	    if ((outlen  & 0xffffffffL)
				!= CKYBuffer_GetLongLE(in, offset+len-4)) {
		break; /* didn't decode the full length */
	    }
	    /* At this point it''s pretty likely we have a gzip trailer. Verify
	     * the crc32 values to make sure there hasn't been any corruption.
	     */
	    if (calc_crc32(CKYBuffer_Data(out), outlen) != 
				CKYBuffer_GetLongLE(in,offset+len-8)) {
		break; /* CRC didn't match */
	    }
 	    /* This was valid gzip data, and we've successfully uncompressed
	     * it. We're now done. */
	    zret=Z_STREAM_END;
	    break;
	case Z_NEED_DICT:
	    /* if we need the dict, it wasn't in the data, 
	     * so it's a data error */
	    zret = Z_DATA_ERROR;
	    break;
	case Z_OK:
	    /* Z_OK means we need more data, expand the buffer and go again.
	     * if we don't need more buffer space, then the input must have
	     * been truncated, that's a data error */
	    if (stream.avail_out != 0) {
		zret = Z_DATA_ERROR;
	    }
	    break;
 	}
    } while (zret == Z_OK);

    /* cleanup */
    if (zret == Z_STREAM_END) {
	zret = Z_OK;
	CKYBuffer_Resize(out, outlen);
    } else {
	CKYBuffer_Resize(out, 0);
    }
    (void)inflateEnd(&stream);
    return zret;
}

/*
 * only necessary for old CAC cards. New CAC cards have to read the
 * whole cert in anyway above....
 */
CKYStatus
Slot::readCACCertificateAppend(CKYBuffer *cert, CKYSize nextSize)
{
    CKYISOStatus apduRC;
    assert(mOldCAC);
    return CACApplet_GetCertificateAppend(conn, cert, nextSize, &apduRC);
}

void
Slot::loadCACCert(CKYByte instance)
{
    CKYStatus status = CKYSUCCESS;
    CKYBuffer cert;
    CKYBuffer rawCert;
    CKYBuffer shmCert;
    CKYSize  nextSize;

    OSTime time = OSTimeNow();

    CKYBuffer_InitEmpty(&cert);
    CKYBuffer_InitEmpty(&rawCert);
    CKYBuffer_InitEmpty(&shmCert);

    //
    // not all CAC cards have all the PKI instances
    // catch the applet selection errors if they don't
    //
    try {
        selectCACApplet(instance);
    } catch(PKCS11Exception& e) {
	// all CAC's must have instance '0', throw the error it
	// they don't.
	if (instance == 0) throw e;
	// If the CAC doesn't have instance '2', and we were updating
	// the shared memory, set it to valid now.
	if ((instance == 2) && !shmem.isValid()) {
	    shmem.setValid();
	}
	return;
    }

    log->log("CAC Cert %d: select CAC applet:  %d ms\n",
						 instance, OSTimeNow() - time);

    if (instance == 0) {
        readCACCertificateFirst(&rawCert, &nextSize, true);
        if(CKYBuffer_Size(&rawCert) <= 1) {
             handleConnectionError();
        }
	log->log("CAC Cert %d: fetch CAC Cert:  %d ms\n", 
						instance, OSTimeNow() - time);
    }

    unsigned short dataVersion = 1;
    CKYBool needRead = 1;

    /* see if it matches the shared memory */
    if (shmem.isValid() &&  shmem.getDataVersion() == dataVersion) {
	shmem.readCACCert(&shmCert, instance);
	CKYSize certSize = CKYBuffer_Size(&rawCert);
	CKYSize shmCertSize = CKYBuffer_Size(&shmCert);
	const CKYByte *shmData = CKYBuffer_Data(&shmCert);

	if (instance != 0) {
	    needRead = 0;
	}

	if (shmCertSize >= certSize) {
	    if (memcmp(shmData, CKYBuffer_Data(&rawCert), certSize) == 0) {
		/* yes it does, no need to read the rest of the cert, use
		 * the cache */
		CKYBuffer_Replace(&rawCert, 0, shmData, shmCertSize);
		needRead = 0;
	    }
	}
	if (!needRead && (shmCertSize == 0)) {	
	    /* no cert of this type, just return */
	    return;
	}
    }
    CKYBuffer_FreeData(&shmCert);

    if (needRead) {
	/* it doesn't, read the new cert and update the cache */
	if (instance == 0) {
	    shmem.clearValid(0);
	    shmem.setVersion(SHMEM_VERSION);
	    shmem.setDataVersion(dataVersion);
	} else {
	    status = readCACCertificateFirst(&rawCert, &nextSize, false);
	
	    if ((status != CKYSUCCESS) || (CKYBuffer_Size(&rawCert) <= 1)) {
		/* CAC only requires the Certificate in pki '0' */
		/* if pki '1' or '2' are empty, treat it as a non-fatal error*/
		if (instance == 2) {
		    /* we've attempted to read all the certs, shared memory
		     * is now valid */
		    shmem.setValid();
		}
		return;
	    }
	}

	if (nextSize) {
	    status = readCACCertificateAppend(&rawCert, nextSize);
	}
	log->log("CAC Cert %d: Fetch rest :  %d ms\n", 
						instance, OSTimeNow() - time);
	if (status != CKYSUCCESS) {
	    handleConnectionError();
	}
	shmem.writeCACCert(&rawCert, instance);
	if (instance == 2) {
	    shmem.setValid();
	}
    }


    log->log("CAC Cert %d: Cert has been read:  %d ms\n",
						instance, OSTimeNow() - time);
    /* new CACs, and old CACs with the high one bit are compressed, 
     * uncompress them */
    if ((CKYBuffer_GetChar(&rawCert,0) & 0x3) == 1) {
	CKYOffset offset = 1;
	int zret = Z_MEM_ERROR;

	/* process the GZIP header if present */
	/* header_id = 0x1f, 0x8b. CM=8. If we ever support something other
	 * than CM=8, we need to change the zlib header below. Currently both
	 * gzip and zlib only support CM=8 (DEFLATE) compression */
	if ((CKYBuffer_GetChar(&rawCert,1) == 0x1f) &&
	    (CKYBuffer_GetChar(&rawCert,2) == 0x8b) &&
	    (CKYBuffer_GetChar(&rawCert,3) == 8)) {
	    CKYByte flags = CKYBuffer_GetChar(&rawCert,4);
	    /* this has a gzip header, not raw data. */
	    offset += 10; /* base size of the gzip header */
	    if (flags & 4) { /* FEXTRA */
		CKYSize len = CKYBuffer_GetShortLE(&rawCert,offset);
		offset += len;
	    }
	    if (flags & 8) { /* FNAME */
		while (CKYBuffer_GetChar(&rawCert,offset) != 0) {
		    offset++;
		}
		offset++;
	    }
	    if (flags & 0x10) { /* FComment */
		while (CKYBuffer_GetChar(&rawCert,offset) != 0) {
		    offset++;
		}
		offset++;
	    }
	    if (flags & 2) { /* FHCRC */
		offset += 2;
	    }
	    offset -= 2;

	    /* add zlib header, so libz will be happy */
	    /* CINFO=7, CM=8, LEVEL=2, DICTFLAG=0, FCHECK= 1c */
	    /* NOTE: the zlib will fail when procssing the trailer. this is
	     * ok because decompress automatically notices the failure and
	     * and checks the gzip trailer. */
	    CKYBuffer_SetChar(&rawCert, offset, 0x78);
	    CKYBuffer_SetChar(&rawCert, offset+1, 0x9c);
	}
	/* uncompress. This expands cert as necessary. */
	zret = decompress(&cert, &rawCert, offset, 
					CKYBuffer_Size(&rawCert)-offset);

	if (zret != Z_OK) {
	    CKYBuffer_FreeData(&rawCert);
	    CKYBuffer_FreeData(&cert);
	    throw PKCS11Exception(CKR_DEVICE_ERROR, 
				"Corrupted compressed CAC/PIV Cert");
	}
    } else {
	CKYBuffer_InitFromBuffer(&cert,&rawCert,1,CKYBuffer_Size(&rawCert)-1);
    }
    CKYBuffer_FreeData(&rawCert);
    log->log("CAC Cert %d: Cert has been uncompressed:  %d ms\n",
						instance, OSTimeNow() - time);

    CACCert certObj(instance, &cert);
    CACPrivKey privKey(instance, certObj);
    CACPubKey pubKey(instance, certObj);
    tokenObjects.push_back(privKey);
    tokenObjects.push_back(pubKey);
    tokenObjects.push_back(certObj);

    if (personName == NULL) {
	const char *name = certObj.getName();
	if (name) {
            personName = strdup(name);
            fullTokenName = true;
	}
    }
}

void
Slot::loadObjects()
{
    // throw away all token objects!

    Transaction trans;
    CKYBuffer header;
    CKYBuffer_InitEmpty(&header);
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS ) {
        handleConnectionError();
    }
    OSTime time = OSTimeNow();


    list<ListObjectInfo> objInfoList;
    std::list<ListObjectInfo>::iterator iter;

    if (state & GOV_CARD) {
	loadCACCert(0);
	loadCACCert(1);
	loadCACCert(2);
	status = trans.end();
	loadReaderObject();
	return;
    }

    selectApplet();
    log->log("time load object: Select Applet (again) %d ms\n",
						OSTimeNow() - time);
    

    status = CKYApplet_ReadObjectFull(conn, COMBINED_ID, 0, 
			CKY_MAX_READ_CHUNK_SIZE, getNonce(), &header, NULL);
    log->log("time load object: ReadCombined Header %d ms\n", 
						OSTimeNow() - time);
    if (status == CKYSCARDERR) { 
        CKYBuffer_FreeData(&header);
        handleConnectionError();
    }
    bool isCombined = (status == CKYSUCCESS) ? true : false;
    try {
	objInfoList = isCombined ? fetchCombinedObjects(&header) 
						: fetchSeparateObjects();
    } catch(PKCS11Exception& e) {
	CKYBuffer_FreeData(&header);
	throw(e);
    }
    log->log("time load object: Fetch %d ms\n", OSTimeNow() - time);
    CKYBuffer_FreeData(&header);
    status = trans.end();

    //
    // load up the keys, certs and others.
    //
    for( iter = objInfoList.begin(); iter != objInfoList.end(); ++iter ) {
	CKYByte type = getObjectClass(iter->obj.objectID);
        if( type == 'k' ) {
	    CK_OBJECT_HANDLE handle = generateUnusedObjectHandle();
            addKeyObject(tokenObjects, *iter, handle, isCombined);
        } else if( type == 'c' ) {
            // cert attribute object. find the DER encoding
            unsigned short certnum = getObjectIndex(iter->obj.objectID);
            if( certnum > 9 ) {
                //invalid object id
                throw PKCS11Exception(CKR_DEVICE_ERROR,
                    "Invalid object id %08x",iter->obj.objectID);
            }
            std::list<ListObjectInfo>::iterator derCert;
	    /*
	     * Old tokens stored certs separately from the attributes
	     */
	    if (!isCombined) {
        	derCert = find_if(objInfoList.begin(), objInfoList.end(),
                    DERCertObjIDMatch(certnum, *this));
        	if( derCert == objInfoList.end() ) {
                    throw PKCS11Exception(CKR_DEVICE_ERROR,
			"No DER cert object for cert %d\n", certnum);
		}
            }
	    CK_OBJECT_HANDLE handle = generateUnusedObjectHandle();
            addCertObject(tokenObjects, *iter, 
			isCombined ? NULL : &derCert->data, handle);
        } else if ( type == 'C' ) {
	    // This is a DER Cert object (as opposed to a cert attribute
	    // object, 'c' above).  skip it.
        } else if (type == 'd') {
	    CK_OBJECT_HANDLE handle = generateUnusedObjectHandle();
	    addObject(tokenObjects, *iter, handle);
	} else {
            log->log("Ignoring unknown object %08x\n",iter->obj.objectID);
        }
    }
    log->log("time load objects: Process %d ms\n", OSTimeNow() - time);

    loadReaderObject();
}

void
Slot::loadReaderObject(void)
{
    // now generate an Moz "reader" object.
    CK_OBJECT_HANDLE handle = generateUnusedObjectHandle();
    Reader rdr(READER_ID, handle, readerName, &cardATR, mCoolkey);
    tokenObjects.push_back(rdr);
}

void
Slot::closeAllSessions()
{
    sessions.clear();
    log->log("cleared all sessions\n");
}

SessionHandleSuffix
Slot::generateNewSession(Session::Type type)
{
    SessionHandleSuffix suffix;
    SessionIter iter;

    do {
        suffix = (++sessionHandleCounter) & 0x00ffffff;
        iter = findSession(suffix);
    } while( iter != sessions.end() );

    sessions.push_back(Session(suffix, type));

    return suffix;
}

void
SlotList::getSessionInfo(CK_SESSION_HANDLE hSession,
    CK_SESSION_INFO_PTR pInfo)
{

    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->getSessionInfo(suffix, pInfo);

    pInfo->slotID = slotID;
}

void
Slot::ensureTokenPresent()
{
    if( ! isTokenPresent() ) {
        throw PKCS11Exception(CKR_DEVICE_REMOVED);
    }
}

SessionIter
Slot::findSession(SessionHandleSuffix suffix)
{
    return find_if(sessions.begin(), sessions.end(),
        SessionHandleSuffixMatch(suffix));
}

SessionConstIter
Slot::findConstSession(SessionHandleSuffix suffix) const
{
    return find_if(sessions.begin(), sessions.end(),
        SessionHandleSuffixMatch(suffix));
}

void
Slot::getSessionInfo(SessionHandleSuffix handleSuffix,
    CK_SESSION_INFO_PTR pInfo)
{
    refreshTokenState();

    SessionIter iter = findSession(handleSuffix);
    if( iter == sessions.end() ) {
            throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID,
                "Unknown session handle suffix 0x%08x passed to "
                    "getSessionInfo\n", (unsigned long) handleSuffix);
    } else {
        if( iter->getType() == Session::RO ) {
            pInfo->state = isLoggedIn() ?
                CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
            pInfo->flags = CKF_SERIAL_SESSION;
        } else {
            pInfo->state = isLoggedIn() ?
                CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
            pInfo->flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
        }
        pInfo->ulDeviceError = CKYCardConnection_GetLastError(conn);
    }
}

void
SlotList::login(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->login(suffix, pPin, ulPinLen);
}

void
Slot::testNonce()
{
    reverify = false;
    if (!nonceValid) {
	return;
    }
#ifdef notdef
    Transaction trans;
    CKYStatus status = trans.begin(conn);
    try {
        if ( status != CKYSUCCESS ) handleConnectionError();

         selectApplet();
    } catch (PKCS11Exception &) {
	invalidateLogin(true);
	return;
    }

    CKYBuffer data;
    CKYBuffer_InitEmpty(&data);

    status = CKYApplet_ReadObject(conn, 0xffffffff, 0, 1, &nonce, &data, NULL);
    trans.end();
    CKYBuffer_FreeData(&data);
    if( status != CKYSUCCESS )  {
	invalidateLogin(true);
	return;
    }
#else
    invalidateLogin(true);
#endif
}

bool
Slot::isLoggedIn()
{
    if (isVersion1Key) {
	if (reverify) {
	    testNonce();
	}
	return nonceValid;
    }
    return loggedIn;
}

void
Slot::login(SessionHandleSuffix handleSuffix, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
    refreshTokenState();

    if( ! isValidSession(handleSuffix) ) {
        log->log("Invalid session handle suffix 0x%08x passed to "
            "Slot::login\n", (unsigned long) handleSuffix);
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    if (!isVersion1Key) {
	pinCache.invalidate();
	pinCache.set((const char *)pPin, ulPinLen);
    } else if (nonceValid) {
	throw PKCS11Exception(CKR_USER_ALREADY_LOGGED_IN);
    }

    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if(status != CKYSUCCESS ) handleConnectionError();

    if (state & GOV_CARD) {
	selectCACApplet(0);
    } else {
	selectApplet();
    }

    if (isVersion1Key) {
	attemptLogin((const char *)pPin);
    } else if (state & GOV_CARD) {
	attemptCACLogin();
    } else {
	oldAttemptLogin();
    }
}

void
Slot::attemptCACLogin()
{
    loggedIn = false;
    pinCache.invalidate();

    CKYStatus status;
    CKYISOStatus result;

    status = CACApplet_VerifyPIN(conn, 
		(const char *)CKYBuffer_Data(pinCache.get()), 
		mCACLocalLogin, &result);
    if( status == CKYSCARDERR ) {
	handleConnectionError();
    }
    switch( result ) {
      case CKYISO_SUCCESS:
        break;
      case 0x6981:
	pinCache.clearPin();
        throw PKCS11Exception(CKR_PIN_LOCKED);
      default:
	pinCache.clearPin();
	if ((result & 0xff00) == 0x6300) {
            throw PKCS11Exception(CKR_PIN_INCORRECT);
	}
        throw PKCS11Exception(CKR_DEVICE_ERROR, "Applet returned 0x%04x", 
								result);
    }

    pinCache.validate();
    loggedIn = true;
}

void
Slot::oldAttemptLogin()
{
    loggedIn = false;
    pinCache.invalidate();

    CKYStatus status;
    CKYISOStatus result;
    status = CKYApplet_VerifyPinV0(conn, CKY_OLD_USER_PIN_NUM,
		(const char *)CKYBuffer_Data(pinCache.get()), &result);
    if( status == CKYSCARDERR ) {
	handleConnectionError();
    }
    switch( result ) {
      case CKYISO_SUCCESS:
        break;
      case CKYISO_AUTH_FAILED:
	pinCache.clearPin();
        throw PKCS11Exception(CKR_PIN_INCORRECT);
      case CKYISO_IDENTITY_BLOCKED:
	pinCache.clearPin();
        throw PKCS11Exception(CKR_PIN_LOCKED);
      default:
	pinCache.clearPin();
        throw PKCS11Exception(CKR_DEVICE_ERROR, "Applet returned 0x%04x", 
								result);
    }

    pinCache.validate();
    loggedIn = true;
}

// should already be in a transaction, and applet selected
void
Slot::attemptLogin(const char *pin)
{
    CKYStatus status;
    CKYISOStatus result;
    status = CKYApplet_VerifyPIN(conn, CKY_USER_PIN_NUM, pin, &nonce, &result);
    if( status == CKYSCARDERR ) {
	handleConnectionError();
    }

    switch( result ) {
      case CKYISO_SUCCESS:
        break;
      case CKYISO_AUTH_FAILED:
        throw PKCS11Exception(CKR_PIN_INCORRECT);
      case CKYISO_IDENTITY_BLOCKED:
        throw PKCS11Exception(CKR_PIN_LOCKED);
      default:
        throw PKCS11Exception(CKR_DEVICE_ERROR,
            "Applet returned 0x%04x", result);
    }
    nonceValid = true;

}

void
SlotList::logout(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->logout(suffix);
}

//
// The old "logout All" from pre-version 1 CoolKeys.
//
void
Slot::oldLogout()
{
    invalidateLogin(true);

    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS) handleConnectionError();

    selectApplet();

    status = CKYApplet_LogoutAllV0(conn, NULL);
    if (status != CKYSUCCESS) {
	if (status == CKYSCARDERR) {
	    handleConnectionError();
	}
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }
}

//
//
void
Slot::CACLogout()
{
    /* use get properties which has the side effect of logging out */
    invalidateLogin(true);
}

void
Slot::logout(SessionHandleSuffix suffix)
{
    refreshTokenState();

    if( !isValidSession(suffix) ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    if (state & GOV_CARD) {
	CACLogout();
	return;
    }

    if (!isVersion1Key) {
	oldLogout();
	return;
    }

    if (!nonceValid) {
	throw PKCS11Exception(CKR_USER_NOT_LOGGED_IN);
    }

    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS) handleConnectionError();

    status = CKYApplet_Logout(conn, CKY_USER_PIN_NUM, getNonce(), NULL);
    invalidateLogin(true);
    if (status != CKYSUCCESS) {
	if (status == CKYSCARDERR) {
	    handleConnectionError();
	}
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }

}

void
SlotList::findObjectsInit(CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->findObjectsInit(suffix, pTemplate, ulCount);
}

void
Slot::findObjectsInit(SessionHandleSuffix suffix, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
    refreshTokenState();

    SessionIter session = findSession(suffix);
    if( session == sessions.end() ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    session->foundObjects.clear();

    ObjectConstIter iter;
    for( iter = tokenObjects.begin(); iter != tokenObjects.end(); ++iter) {
        if( iter->matchesTemplate(pTemplate, ulCount) ) {
            log->log("C_FindObjectsInit found matching object 0x%08x\n",
                iter->getHandle());
            session->foundObjects.push_back(iter->getHandle());
        }
    }

    session->curFoundObject = session->foundObjects.begin();
}

void
SlotList::findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
        CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->findObjects(suffix, phObject,
        ulMaxObjectCount, pulObjectCount);
}

void
Slot::findObjects(SessionHandleSuffix suffix, CK_OBJECT_HANDLE_PTR phObject,
        CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    refreshTokenState();

    SessionIter session = findSession(suffix);
    if( session == sessions.end() ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    unsigned int objectsReturned = 0;
    while( objectsReturned < ulMaxObjectCount &&
        session->curFoundObject != session->foundObjects.end() )
    {
        phObject[objectsReturned++] = *(session->curFoundObject++);
    }

    *pulObjectCount = objectsReturned;
}

void
SlotList::getAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
    const
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->getAttributeValue(suffix, hObject,
        pTemplate, ulCount);
}

void
Slot::getAttributeValue(SessionHandleSuffix suffix,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    refreshTokenState();

    if( ! isValidSession(suffix) ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    ObjectConstIter iter = find_if(tokenObjects.begin(), tokenObjects.end(),
        ObjectHandleMatch(hObject));

    if( iter == tokenObjects.end() ) {
        throw PKCS11Exception(CKR_OBJECT_HANDLE_INVALID);
    }

    iter->getAttributeValue(pTemplate, ulCount, log);
}

void
SlotList::signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->signInit(suffix, pMechanism, hKey);
}

void
SlotList::decryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->decryptInit(suffix, pMechanism, hKey);
}

void
SlotList::sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->sign(suffix, pData, ulDataLen,
        pSignature, pulSignatureLen);
}

void
SlotList::decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData,
        CK_ULONG_PTR pulDecryptedDataLen)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->decrypt(suffix, pData, ulDataLen,
        pDecryptedData, pulDecryptedDataLen);
}

void
SlotList::seedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->seedRandom(suffix, pData, ulDataLen);
}

void
SlotList::generateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen)
{
    CK_SLOT_ID slotID;
    SessionHandleSuffix suffix;

    decomposeSessionHandle(hSession, slotID, suffix);

    slots[slotIDToIndex(slotID)]->generateRandom(suffix, pData, ulDataLen);
}

void
Slot::ensureValidSession(SessionHandleSuffix suffix)
{
    if( ! isValidSession(suffix) ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
}

//
// Looks up an object and pulls the key number from the Muscle Object ID.
// Keys in Muscle have IDs of the form 'kn  ', where 'n' is the key number
// from 0-9.
//
CKYByte
Slot::objectHandleToKeyNum(CK_OBJECT_HANDLE hKey)
{
    ObjectConstIter iter = find_if(tokenObjects.begin(), tokenObjects.end(),
        ObjectHandleMatch(hKey));

    if( iter == tokenObjects.end() ) {
        // no such object
        throw PKCS11Exception(CKR_KEY_HANDLE_INVALID);
    }

    if( getObjectClass(iter->getMuscleObjID()) != 'k' ) {
        throw PKCS11Exception(CKR_KEY_HANDLE_INVALID);
    }
    unsigned short keyNum = getObjectIndex(iter->getMuscleObjID());
    if( keyNum > 9 ) {
        throw PKCS11Exception(CKR_KEY_HANDLE_INVALID);
    }
    return keyNum & 0xFF;
}

void
Slot::signInit(SessionHandleSuffix suffix, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey)
{
    refreshTokenState();
    SessionIter session = findSession(suffix);
    if( session == sessions.end() ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
    session->signatureState.initialize(objectHandleToKeyNum(hKey));
}

void
Slot::decryptInit(SessionHandleSuffix suffix, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey)
{
    refreshTokenState();
    SessionIter session = findSession(suffix);
    if( session == sessions.end() ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
    session->decryptionState.initialize(objectHandleToKeyNum(hKey));
}

/**
 * Padding algorithm defined in RSA's PKCS #1.
 * to: pre-allocated buffer to receive the padded data
 * toLen: the length of the buffer. This should be the same as the size
 *      of the RSA modulus.  (toLen - 3) > fromLen.
 * from: data to be padded.
 * fromLen: size of data to be padded. fromLen < (toLen-3).
 * Returns: nonzero for success, zero for failure.
 */
static void
padRSAType1(const CKYBuffer *raw, CKYBuffer *padded)
{
    int i = 0;
    unsigned int padLen = CKYBuffer_Size(padded) - 3 - CKYBuffer_Size(raw);

    /* First byte: 00 */
    CKYBuffer_SetChar(padded, i++, 0x00);

    /* Second Byte: Block Type == 01 */
    CKYBuffer_SetChar(padded, i++, 0x01);

    /* Padding String, each byte is 0xFF for block type 01 */
    CKYBuffer_SetChars(padded, i, 0xFF, padLen);
    i += padLen;

    /* Separator byte: 00 */
    CKYBuffer_SetChar(padded, i++, 0x00);

    /* Finally, the data */
    CKYBuffer_Replace(padded, i, CKYBuffer_Data(raw), CKYBuffer_Size(raw));
}

static void
stripRSAPadding(CKYBuffer *stripped, const CKYBuffer *padded)
{
    unsigned int size = CKYBuffer_Size(padded);
    if( size < 2 ) {
        throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
    }
    if( CKYBuffer_GetChar(padded,0) != 0 ) {
        throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
    }

    unsigned int dataStart = 3;

    CKYByte blockType = CKYBuffer_GetChar(padded, 1);
    // There are three block types in PKCS #1 padding: 00, 01, and 02.
    switch(blockType) {
      case 0x00:
        // The padding string is all zeroes. The first nonzero byte
        // is the beginning of the data.
        for( ; dataStart < size; ++dataStart ) {
            if( CKYBuffer_GetChar(padded,dataStart) != 0 ) {
                break;
            }
        }
        if( dataStart == size ) {
            throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
        }
        break;
      case 0x01:
        // The padding string is all 0xFF, followed by a 0x00 separator byte,
        // and then the data.
        for( ; dataStart < size; ++dataStart ) {
            if( CKYBuffer_GetChar(padded,dataStart) == 0xff ) {
                // padding, continue;
            } else if( CKYBuffer_GetChar(padded,dataStart) == 0x00 ) {
                // end of padding
                break;
            } else {
                // invalid character
                throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
            }
        }
        if( dataStart == size  ) {
            // we never found the separator byte
            throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
        }
        dataStart++; // data starts after separator byte
        break;
      case 0x02:
        // padding is non-zero. First non-zero byte is the separator,
        // and then the data.
        for( ; dataStart < size; ++dataStart) {
            if( CKYBuffer_GetChar(padded,dataStart) == 0x00 ) {
                break;
            }
        }
        if( dataStart == size ) {
            // we never found the separator byte
            throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID);
        }
        dataStart++; // data starts after separator byte
        break;
      default:
        throw PKCS11Exception(CKR_ENCRYPTED_DATA_INVALID,
            "Unknown PKCS#1 block type %x", blockType);
    }

    CKYStatus status = CKYBuffer_Replace(stripped, 0, 
		CKYBuffer_Data(padded)+dataStart, size-dataStart);
    if (status != CKYSUCCESS) {
	throw PKCS11Exception(CKR_HOST_MEMORY);
    }
}

class RSASignatureParams : public CryptParams {
  public:
    RSASignatureParams(unsigned int keysize) : CryptParams(keysize) { }

    CKYByte getDirection() const { return CKY_DIR_ENCRYPT; }

    CryptOpState& getOpState(Session& session) const {
        return session.signatureState;
    }

    void padInput(CKYBuffer *paddedInput, const CKYBuffer *unpaddedInput) const {
        // RSA_NO_PAD requires RSA PKCS #1 Type 1 padding
  	CKYStatus status = CKYBuffer_Resize(paddedInput,getKeySize()/8);
	if (status != CKYSUCCESS) {
	    throw PKCS11Exception(CKR_HOST_MEMORY);
	}
        padRSAType1(unpaddedInput, paddedInput);
        return;
    }

    void
    unpadOutput(CKYBuffer *unpaddedOutput, const CKYBuffer *paddedOutput) const {
        // no need to unpad ciphertext
	CKYBuffer_Replace(unpaddedOutput, 0, CKYBuffer_Data(paddedOutput),
					CKYBuffer_Size(paddedOutput));
	
    }
};

class RSADecryptParams: public CryptParams {
  public:
    RSADecryptParams(unsigned int keysize) : CryptParams(keysize) { }

    CKYByte getDirection() const { return CKY_DIR_DECRYPT; }

    CryptOpState& getOpState(Session& session) const {
        return session.decryptionState;
    }

    void padInput(CKYBuffer *paddedInput, const CKYBuffer *unpaddedInput) const {
        // no need to unpad ciphertext
	CKYBuffer_Replace(paddedInput, 0, CKYBuffer_Data(unpaddedInput),
					CKYBuffer_Size(unpaddedInput));
    }

    void
    unpadOutput(CKYBuffer *unpaddedOutput, const CKYBuffer *paddedOutput) const {
        // strip off PKCS #1 padding
        stripRSAPadding( unpaddedOutput, paddedOutput );
	return;
    }
};

void
Slot::sign(SessionHandleSuffix suffix, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen)
{
    RSASignatureParams params(CryptParams::DEFAULT_KEY_SIZE);
    cryptRSA(suffix, pData, ulDataLen, pSignature, pulSignatureLen,
        params);
}

void
Slot::decrypt(SessionHandleSuffix suffix, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData,
        CK_ULONG_PTR pulDecryptedDataLen)
{
    RSADecryptParams params(CryptParams::DEFAULT_KEY_SIZE);
    cryptRSA(suffix, pData, ulDataLen, pDecryptedData, pulDecryptedDataLen,
        params);
}

void
Slot::cryptRSA(SessionHandleSuffix suffix, CK_BYTE_PTR pInput,
        CK_ULONG ulInputLen, CK_BYTE_PTR pOutput,
        CK_ULONG_PTR pulOutputLen, CryptParams& params)
{
    refreshTokenState();
    SessionIter session = findSession(suffix);
    if( session == sessions.end() ) {
        throw PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
    // version 1 keys may not need login. We catch the error
    // on the operation. The token will not allow us to sign with
    // a protected key unless we are logged in.
    // can be removed when version 0 support is depricated.
    if (!isVersion1Key && ! isLoggedIn() ) {
        throw PKCS11Exception(CKR_USER_NOT_LOGGED_IN);
    }
    CryptOpState& opState = params.getOpState(*session);
    CKYBuffer *result = &opState.result;
    CKYByte keyNum = opState.keyNum;

    unsigned int keySize = getKeySize(keyNum);

    if(keySize != CryptParams::DEFAULT_KEY_SIZE)
        params.setKeySize(keySize);

    if( CKYBuffer_Size(result) == 0 ) {
        // we haven't already peformed the decryption, so do it now.
        if( pInput == NULL || ulInputLen == 0) {
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }
	// OK, this is gross. We should get our own C++ like buffer
        // management at this point. This code has nothing to do with
	// the applet, it shouldn't be using applet specific buffers.
        CKYBuffer input;
        CKYBuffer inputPad;
        CKYBuffer output;
        CKYBuffer_InitEmpty(&output);
        CKYBuffer_InitEmpty(&inputPad);
	CKYStatus status = CKYBuffer_InitFromData(&input, pInput, ulInputLen);
 	if (status != CKYSUCCESS) {
	    throw PKCS11Exception(CKR_HOST_MEMORY);
  	}
	try {
	    params.padInput(&inputPad, &input);
            performRSAOp(&output, &inputPad, keyNum, params.getDirection());
	    params.unpadOutput(result, &output);
	    CKYBuffer_FreeData(&input);
	    CKYBuffer_FreeData(&inputPad);
	    CKYBuffer_FreeData(&output);
	} catch(PKCS11Exception& e) {
	    CKYBuffer_FreeData(&input);
	    CKYBuffer_FreeData(&inputPad);
	    CKYBuffer_FreeData(&output);
	    throw(e);
	}
    }

    if( pulOutputLen == NULL ) {
        throw PKCS11Exception(CKR_DATA_INVALID,
            "output length is NULL");
    }

    if( pOutput != NULL ) {
        if( *pulOutputLen < CKYBuffer_Size(result) ) {
            *pulOutputLen = CKYBuffer_Size(result);
            throw PKCS11Exception(CKR_BUFFER_TOO_SMALL);
        }
        memcpy(pOutput, CKYBuffer_Data(result), CKYBuffer_Size(result));
    }
    *pulOutputLen = CKYBuffer_Size(result);
}

const CKYBuffer *
Slot::getNonce()
{
    if (!isVersion1Key) {
	return NULL;
    }
    return &nonce;
}

void
Slot::performRSAOp(CKYBuffer *output, const CKYBuffer *input, 
					CKYByte keyNum, CKYByte direction)
{
    //
    // establish a transaction
    //
    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS ) handleConnectionError();

    //
    // select the applet
    //
    if (state & GOV_CARD) {
	selectCACApplet(keyNum);
    } else {
	selectApplet();
    }

    CKYISOStatus result;
    int loginAttempted = 0;
retry:
    if (state & PIV_CARD) {
        status = PIVApplet_SignDecrypt(conn, pivKey, input, output, &result);
    } else if (state & CAC_CARD) {
        status = CACApplet_SignDecrypt(conn, input, output, &result);
    } else {
        status = CKYApplet_ComputeCrypt(conn, keyNum, CKY_RSA_NO_PAD, direction,
		input, NULL, output, getNonce(), &result);
    } 
    /* map the ISO not logged in code to the coolkey one */
    if ((result == CKYISO_CONDITION_NOT_SATISFIED) ||
        (result == CKYISO_SECURITY_NOT_SATISFIED)) {
	result = (CKYStatus) CKYISO_UNAUTHORIZED;
    }
    if (status != CKYSUCCESS) {
	if ( status == CKYSCARDERR ) {
	    handleConnectionError();
	}
        if (result == CKYISO_DATA_INVALID) {
            throw PKCS11Exception(CKR_DATA_INVALID);
	}
	// version0 keys could be logged out in the middle by someone else,
	// reauthenticate... This code can go away when we depricate.
        // version0 applets.
	if (!isVersion1Key && !loginAttempted  && pinCache.isValid() &&
					(result == CKYISO_UNAUTHORIZED)) {
	    // try to reauthenticate 
	    try {
		if (state & GOV_CARD) {
		    attemptCACLogin();
		} else {
		    oldAttemptLogin();
		}
	    } catch(PKCS11Exception& ) {
		// attemptLogin can throw things like CKR_PIN_INCORRECT
		// that don't make sense from a crypto operation. This is
		// a result of pin caching. We will reformat any login
		// exception to a CKR_DEVICE_ERROR.
		throw PKCS11Exception(CKR_DEVICE_ERROR);
	    }
	    loginAttempted = true;
	    goto retry; // easier to understand than a while loop in this case.
	}
 	throw PKCS11Exception( result == CKYISO_UNAUTHORIZED ?
		 CKR_USER_NOT_LOGGED_IN : CKR_DEVICE_ERROR);
    }
}

void
Slot::seedRandom(SessionHandleSuffix suffix, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen)
{
    if (state & GOV_CARD) {
	/* should throw unsupported */
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }

    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS ) handleConnectionError();

    CKYBuffer random;
    CKYBuffer seed;
    CKYOffset offset = 0;
    CKYISOStatus result;
    int i;

    CKYBuffer_InitEmpty(&random);
    CKYBuffer_InitFromData(&seed, pData, ulDataLen);


    while (ulDataLen) {
	CKYByte len = (CKYByte) MIN(ulDataLen, 0xff);

	status = CKYApplet_GetRandom(conn, &random, len, &result);
	if (status != CKYSUCCESS) break;

	for (i=0; i < len ; i++) {
	    CKYBuffer_SetChar(&random, i, 
			CKYBuffer_GetChar(&random,i) ^
			CKYBuffer_GetChar(&seed,i+offset));
	}
	status = CKYApplet_SeedRandom(conn, &random, &result);
	if (status != CKYSUCCESS) break;

	ulDataLen -= (unsigned char)len;
	offset += (unsigned char)len;
    }

    CKYBuffer_FreeData(&random);
    CKYBuffer_FreeData(&seed);

    if (status != CKYSUCCESS) {
	if ( status == CKYSCARDERR ) {
	    handleConnectionError();
	}
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }
}

void
Slot::generateRandom(SessionHandleSuffix suffix, const CK_BYTE_PTR pData,
        CK_ULONG ulDataLen)
{
    if (state & GOV_CARD) {
	/* should throw unsupported */
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }

    Transaction trans;
    CKYStatus status = trans.begin(conn);
    if( status != CKYSUCCESS ) handleConnectionError();

    CKYBuffer random;
    CKYBuffer_InitEmpty(&random);

    CKYISOStatus result;

    while (ulDataLen) {
	CKYByte len = (CKYByte) MIN(ulDataLen, 0xff);

	status = CKYApplet_GetRandomAppend(conn, &random, len, &result);
	if (status != CKYSUCCESS) break;

	ulDataLen -= (unsigned char)len;
    }
    CKYBuffer_FreeData(&random);

    if (status != CKYSUCCESS) {
	if ( status == CKYSCARDERR ) {
	    handleConnectionError();
	}
	throw PKCS11Exception(CKR_DEVICE_ERROR);
    }
}

#define MAX_NUM_KEYS 8
unsigned int
Slot::getKeySize(CKYByte keyNum)
{
    unsigned int keySize = CryptParams::DEFAULT_KEY_SIZE;
    int modSize = 0;

    if(keyNum >= MAX_NUM_KEYS) {
        return keySize;
    }

    ObjectConstIter iter;
    iter = find_if(tokenObjects.begin(), tokenObjects.end(),
        KeyNumMatch(keyNum,*this));

    if( iter == tokenObjects.end() ) {
        return keySize;
    }

    CKYBuffer const *modulus = iter->getAttribute(CKA_MODULUS);

    if(modulus) {
        modSize = CKYBuffer_Size(modulus);
        if(CKYBuffer_GetChar(modulus,0) == 0x0) {
            modSize--;
        }
        if(modSize > 0)
            keySize = modSize * 8;
    }

    return keySize;
}
