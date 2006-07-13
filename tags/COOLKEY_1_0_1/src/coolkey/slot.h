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

#ifndef COOLKEY_SLOT_H
#define COOLKEY_SLOT_H

#include "locking.h"
#include "log.h"
#include "cky_applet.h"
#include <string.h>
#include <algorithm>
#include "object.h"
#include "machdep.h"
#include <assert.h>

using std::list;
using std::find;
using std::find_if;

class Transaction {

private:
   CKYCardConnection *conn;

   Transaction(const Transaction&) {} // not allowed
   Transaction& operator=(const Transaction&) {return *this;} // not allowed
public:
    Transaction() : conn(0) { }
    CKYStatus begin(CKYCardConnection *conn_) {
	CKYStatus status;
	status = CKYCardConnection_BeginTransaction(conn_);
	if (status == CKYSUCCESS) {
	    conn = conn_;
	}
	return status;
    }
    CKYStatus end() {
	CKYStatus status = CKYSUCCESS;
	CKYCardConnection *conn_ = conn;

	conn = NULL;
	if (conn_) {
	    status = CKYCardConnection_EndTransaction(conn_);
	}
	return status;
    }
    ~Transaction() { if (conn) end(); }
};

#ifdef USE_SHMEM

#define SHMEM_VERSION 0x0100 // 1.0

class SlotMemSegment {
private:
    char *segmentAddr;
    int   segmentSize;
    SHMem *segment;  // machine independed shared memory object
public:
    SlotMemSegment(const char *readerName);
    ~SlotMemSegment();

    bool CUIDIsEqual(const CKYBuffer *cuid) const;
    unsigned short getVersion() const;
    unsigned short getDataVersion() const;
    void setCUID(const CKYBuffer *cuid);
    void setVersion(unsigned short version);
    void setDataVersion(unsigned short version);
    bool isValid() const;
    int size() const;
    const unsigned char *getCUID() const;
    void readHeader(CKYBuffer *data) const;
    void writeHeader(const CKYBuffer *data);
    void setSize(int size);
    void readData(CKYBuffer *data) const;
    void writeData(const CKYBuffer *data);
    void readCACCert(CKYBuffer *data, CKYByte instance) const;
    void writeCACCert(const CKYBuffer *data, CKYByte instance);
    void clearValid(CKYByte instance);
    void setValid();
};
#endif

struct ListObjectInfo {
    CKYAppletRespListObjects obj;
    CKYBuffer data;

    ListObjectInfo(const ListObjectInfo &cpy) {
	obj = cpy.obj;
 	CKYBuffer_InitFromCopy(&data,&cpy.data);
    }
    ListObjectInfo &operator=(const ListObjectInfo& cpy ) {
	obj = cpy.obj;
	CKYBuffer_Replace(&data, 0, CKYBuffer_Data(&cpy.data),
				CKYBuffer_Size(&cpy.data));
	return *this;
    }
    bool operator==(const ListObjectInfo& cmp) const {
        if( obj.objectID != cmp.obj.objectID )
            return false;
        if( obj.objectSize!=cmp.obj.objectSize )
            return false;
        if( obj.readACL != cmp.obj.readACL ) 
            return false;
        if( obj.writeACL != cmp.obj.writeACL ) 
            return false;
        if( obj.deleteACL != cmp.obj.deleteACL ) 
            return false;
        if( !CKYBuffer_IsEqual(&data,&cmp.data) )
            return false;
        return true;
    }
    ListObjectInfo(void) {
	memset(&obj, 0, sizeof(obj));
	CKYBuffer_InitEmpty(&data);
    }
    ~ListObjectInfo() {
	CKYBuffer_FreeData(&data);
    }
};

//
// The most significant byte of a session handle is the slot ID.
// The three most significant bytes, the SessionHandleSuffix, are controlled
// by the slot itself.
//
class SessionHandleSuffix {
  private:
    CK_SESSION_HANDLE value;
  public:
    SessionHandleSuffix() : value(0) { }
    SessionHandleSuffix(CK_SESSION_HANDLE val) {
        value = val & 0x00ffffff;
    }

    operator CK_SESSION_HANDLE() {
        return value;
    }

    SessionHandleSuffix& operator=(CK_SESSION_HANDLE val) {
        value = val & 0x00ffffff;
        return *this;
    }

    bool operator==(const SessionHandleSuffix&cmp) const {
        return value == cmp.value;
    }
};

struct PinCache {
  private:
    CKYBuffer cachedPin;
    bool valid;

    PinCache(const PinCache &cpy) {} // not allowed
    PinCache  &operator=(const PinCache &cpy) 
			{ return *this ; }  // not allowed

  public:
    PinCache() : valid(false) { CKYBuffer_InitEmpty(&cachedPin); }
    ~PinCache() { 
	CKYBuffer_Zero(&cachedPin); /* zero buffer before freeing it so
				    * we don't get passwords on the heap */
	CKYBuffer_FreeData(&cachedPin); }
    void set(const char *newPin, unsigned long pinLen) {
	CKYBuffer_Zero(&cachedPin);
	CKYBuffer_Replace(&cachedPin, 0, (const CKYByte *)newPin, pinLen);
	CKYBuffer_AppendChar(&cachedPin, 0);
    }
    void clearPin() { CKYBuffer_Zero(&cachedPin); }
    void invalidate() { valid = false; }
    void validate() { valid = true; }
    const CKYBuffer *get() const { return &cachedPin; }
    bool isValid() const { return valid; }
};

inline unsigned int slotIDToIndex(CK_SLOT_ID slotID) {
    return slotID - 1;
}

inline CK_SLOT_ID slotIndexToID(unsigned int index) {
    return index + 1;
}

typedef list<PKCS11Object> ObjectList;
typedef ObjectList::iterator ObjectIter;
typedef ObjectList::const_iterator ObjectConstIter;

typedef list<CK_OBJECT_HANDLE> ObjectHandleList;
typedef ObjectHandleList::iterator ObjectHandleIter;

class CryptOpState {
  public:
    enum State { NOT_INITIALIZED, IN_PROCESS, FINALIZED };
    State state;
    CKYByte keyNum;
    CKYBuffer result;

    CryptOpState() : state(NOT_INITIALIZED), keyNum(0) 
				{ CKYBuffer_InitEmpty(&result); }
    CryptOpState(const CryptOpState &cpy) : 
				state(cpy.state), keyNum(cpy.keyNum) { 
	CKYBuffer_InitFromCopy(&result, &cpy.result);
    }
    CryptOpState &operator=(const CryptOpState &cpy) {
	state = cpy.state,
	keyNum = cpy.keyNum;
	CKYBuffer_Replace(&result, 0, CKYBuffer_Data(&cpy.result),
				CKYBuffer_Size(&cpy.result));
	return *this;
    }
    ~CryptOpState() { CKYBuffer_FreeData(&result); }
    void initialize(CKYByte keyNum) {
        state = IN_PROCESS;
        this->keyNum = keyNum;
        CKYBuffer_Resize(&result, 0);
    }
};

class Session {
  public:
    enum Type { RO, RW };
  private:
    SessionHandleSuffix handleSuffix;
    Type type;

  public:
    Session(SessionHandleSuffix h, Type t) : handleSuffix(h), type(t) { }
    ~Session() { }

    SessionHandleSuffix getHandleSuffix() const { return handleSuffix; }
    Type getType() const { return type; }

    bool operator==(const Session& cmp) const {
        return handleSuffix == cmp.handleSuffix;
    }

    // the results of FindObjectsInit() are stored here and passed out
    // to FindObjects().
    ObjectHandleList foundObjects;   
    ObjectHandleIter curFoundObject;

    CryptOpState signatureState;
    CryptOpState decryptionState;
};

typedef list<Session> SessionList;
typedef SessionList::iterator SessionIter;
typedef SessionList::const_iterator SessionConstIter;

class CryptParams {
  private:
    unsigned int keySize; // in bits
  protected:
    unsigned int getKeySize() const { return keySize; }
  public:
    // !!!XXX hack. The right way to get the key size is to get all the
    // key information from the token with MSCListKeys, the same way
    // we get all the object information with MSCListObjects.
    enum { FIXED_KEY_SIZE = 1024 };


    CryptParams(unsigned int keySize_) : keySize(keySize_) { }
    virtual ~CryptParams() { }

    // returns the Muscle 'direction' constant for the operation,
    // required for the MSCComputeCrypt command
    virtual CKYByte getDirection() const = 0;

    // pulls the proper state object out of a session.
    virtual CryptOpState& getOpState(Session& session) const = 0;

    // performs any padding required on the input to the operation
    virtual void padInput(CKYBuffer *paddedOutput,
				 const CKYBuffer *unpaddedInput) const = 0;

    // performs any unpadding required on the output from the operation
    virtual void unpadOutput(CKYBuffer *unpaddedInout,
				 const CKYBuffer *paddedOutput) const = 0;
};

class Slot {

  public:
    enum SlotState {
        UNKNOWN = 0x01,
        CARD_PRESENT = 0x02,
        ATR_MATCH = 0x04,
        APPLET_SELECTABLE = 0x08,
        APPLET_PERSONALIZED = 0x10,
        CAC_CARD = 0x20
    };
    enum {
	NONCE_SIZE = 8
    };

  private:
    Log *log;
    char *readerName;
    char *personName;
    char *manufacturer;
    //char *model;
    CK_VERSION hwVersion;
    CK_VERSION tokenFWVersion;
    bool slotInfoFound;
    CKYCardContext* context;
    CKYCardConnection* conn;
    unsigned long state; // = UNKNOWN
    PinCache pinCache;
    bool loggedIn;
    bool reverify;
    bool nonceValid;
    CKYBuffer nonce;
    CKYBuffer cardATR;
    CKYBuffer mCUID;
    bool isVersion1Key;
    bool needLogin;
    long publicFree;
    long publicTotal;
    long privateFree;
    bool fullTokenName;
    bool mCoolkey;

    //enum { RW_SESSION_HANDLE = 1, RO_SESSION_HANDLE = 2 };

#ifdef USE_SHMEM
    SlotMemSegment shmem;
#endif

    SessionList sessions;
    unsigned int sessionHandleCounter;

    ObjectList tokenObjects;
    CK_OBJECT_HANDLE objectHandleCounter;
    CK_OBJECT_HANDLE generateUnusedObjectHandle();

    SessionIter findSession(SessionHandleSuffix suffix);
    SessionConstIter findConstSession(SessionHandleSuffix suffix) const;

    void closeAllSessions();
    SessionHandleSuffix generateNewSession(Session::Type type);

    bool cardStateMayHaveChanged();
    void connectToToken();
    void refreshTokenState();
    void disconnect();
    void handleConnectionError();
    void ensureTokenPresent();
    void readSlotInfo();
    void readCUID();
    void initEmpty();

    // formatting helpers
    // data will be formated to fit in the supplied buffers, padded with
    // ascii blanks. size of the buffers is specifed by maxSize.
    //
    void makeLabelString(char *man, int maxSize, const unsigned char *cuid);
    void makeManufacturerString(char *man, int maxSize, 
						const unsigned char *cuid);
    void makeModelString(char *man, int maxSize, const unsigned char *cuid);
    void makeSerialString(char *man, int maxSize, const unsigned char *cuid);
    void makeCUIDString(char *man, int maxSize, const unsigned char *cuid);

    // login helpers
    void invalidateLogin(bool hard);
    const CKYBuffer *getNonce();
    const CKYBuffer *getATR();
    bool isLoggedIn();
    bool needLoggedIn();
    void testNonce();

    void addKeyObject(list<PKCS11Object>& objectList,
        const ListObjectInfo& info, CK_OBJECT_HANDLE handle, bool isCombined);
    void addCertObject(list<PKCS11Object>& objectList, 
	const ListObjectInfo& certAttrs,
	const CKYBuffer *derCert, CK_OBJECT_HANDLE handle);
    void addObject(list<PKCS11Object>& objectList,
        const ListObjectInfo& info, CK_OBJECT_HANDLE handle);

    void ensureValidSession(SessionHandleSuffix suffix);

    list<ListObjectInfo> getObjectList();
    list<ListObjectInfo> fetchCombinedObjects(const CKYBuffer *header);
    list<ListObjectInfo> fetchSeparateObjects();

    void selectApplet();
    void selectCACApplet(CKYByte instance);
    void unloadObjects();
    void loadCACObjects();
    void loadCACCert(CKYByte instance);
    void loadObjects();
    void loadReaderObject();

    void attemptLogin(const char *pin);
    void attemptCACLogin();
    void oldAttemptLogin();
    void oldLogout(void);
    void CACLogout(void);

    void readMuscleObject(CKYBuffer *obj, unsigned long objID, 
							unsigned int objSize);

    void performSignature(CKYBuffer *sig, const CKYBuffer *unpaddedInput, 
							CKYByte keyNum);
    void performDecryption(CKYBuffer *data, const CKYBuffer *input, CKYByte keyNum);

    void cryptRSA(SessionHandleSuffix suffix, CK_BYTE_PTR pInput,
        CK_ULONG ulInputLen, CK_BYTE_PTR pOutput,
        CK_ULONG_PTR pulOutputLen, const CryptParams& params);

    void performRSAOp(CKYBuffer *out, const CKYBuffer *input, CKYByte keyNum, 
							     CKYByte direction);

    void processComputeCrypt(CKYBuffer *result, const CKYAPDU *apdu);

    CKYByte objectHandleToKeyNum(CK_OBJECT_HANDLE hKey);
    Slot(const Slot &cpy)
#ifdef USE_SHMEM
	: shmem(readerName)
#endif
	{} // not allowed
    Slot  &operator=(const Slot &cpy) { return *this; }  // not allowed
  public:
    Slot(const char *readerName, Log *log, CKYCardContext* context);
    ~Slot();

    // Returns TRUE if the token is present from the point of view of PKCS #11.
    // This will occur if a card is present, our applet is selectable,
    // and the applet is in a personalized state.
    bool isTokenPresent();

    CK_RV getSlotInfo(CK_SLOT_INFO_PTR pSlotInfo);
    CK_RV getTokenInfo(CK_TOKEN_INFO_PTR pTokenInfo);

    // future versions may have different defintions of object classes
    // this function may need to look a applet or protocol version
    // to parse things correctly. Right now the class is a single character
    // in the top byte of the objectID. the index is the second byte
    // in bdc ascii (values 0-9).
    char getObjectClass(unsigned long objectID) const {
        return (char) (objectID >> 24) & 0xff;
    }
    unsigned short getObjectIndex(unsigned long objectID) const {
        return (char )((objectID >> 16) & 0xff) - '0';
    }


    SessionHandleSuffix openSession(Session::Type type);
    void closeSession(SessionHandleSuffix handleSuffix);

    bool isValidSession(SessionHandleSuffix handleSuffix) const;

    void getSessionInfo(SessionHandleSuffix handleSuffix,
        CK_SESSION_INFO_PTR pInfo);

    void login(SessionHandleSuffix handleSuffix, CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen);

    void logout(SessionHandleSuffix suffix);

    void findObjectsInit(SessionHandleSuffix handleSuffix,
        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

    void findObjects(SessionHandleSuffix suffix, CK_OBJECT_HANDLE_PTR phObject,
        CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);

    void getAttributeValue(SessionHandleSuffix suffix,
        CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

    void signInit(SessionHandleSuffix suffix, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey);

    void sign(SessionHandleSuffix suffix, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen);

    void decryptInit(SessionHandleSuffix suffix, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey);

    void decrypt(SessionHandleSuffix suffix, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData,
        CK_ULONG_PTR pulDecryptedDataLen);

    void seedRandom(SessionHandleSuffix suffix, CK_BYTE_PTR data,
	CK_ULONG len);
    void generateRandom(SessionHandleSuffix suffix, CK_BYTE_PTR data,
	CK_ULONG len);
};

class SlotList {

  private:
    Slot **slots;
    unsigned int numSlots;
    Log *log;
    CKYCardContext *context;
    SCARD_READERSTATE *readerStates;
    unsigned int numReaders;
    OSLock readerListLock;
    bool shuttingDown;


    void decomposeSessionHandle(CK_SESSION_HANDLE hSession, CK_SLOT_ID& slotID,
        SessionHandleSuffix& suffix) const;

    /* the slot list is the list the outside world sees */
    void updateSlotList();
    /* the reader list is the internal list we keep. It is possible that
     * the reader list has more readers on it than the slot list reflects.
     * This is because we can only update the slot list if the application
     * has called 'C_GetSlotList' with a NULL parameter */
    void updateReaderList();

    bool readerExists(const char *readerName, unsigned int *hint = 0);
  public:
    SlotList(Log *log);
    ~SlotList();

    void shutdown(); // close our connection so waits will return.
    int getNumSlots() const { return numSlots; }
    Slot* getSlot(unsigned int index) const {
        assert( index >= 0 && index < numSlots );
        return slots[index];
    }
    CK_RV getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
            CK_ULONG_PTR pulCount);
    CK_RV getInfo(CK_SLOT_INFO_PTR pSlotInfo) const;

    void validateSlotID(CK_SLOT_ID id) const;

    void waitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, 
	CK_VOID_PTR pReserved);

    void openSession(Session::Type type, CK_SLOT_ID slotID,
        CK_SESSION_HANDLE_PTR phSession);

    void closeSession(CK_SESSION_HANDLE sessionHandle);

    bool isValidSession(CK_SESSION_HANDLE sessionID) const;

    void getSessionInfo(CK_SESSION_HANDLE sessionHandle,
        CK_SESSION_INFO_PTR pInfo);

    void login(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen);

    void logout(CK_SESSION_HANDLE hSession);

    void findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount);

    void findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
        CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);

    void getAttributeValue(CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
        const;

    void signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey);

    void sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen);

    void decryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey);

    void decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData,
        CK_ULONG_PTR pulDecryptedDataLen);

    void generateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen);

    void seedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
        CK_ULONG ulDataLen);


};
#endif
