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

#ifndef COOLKEY_OBJECT_H
#define COOLKEY_OBJECT_H

#include "mypkcs11.h"
#include "cky_base.h"
#include <list>
#include "log.h"

using std::list;

/*
 * Sigh PKCS 15 is heavily ASN.1...
 */
const CKYByte  ASN1_BOOLEAN           = 0x01;
const CKYByte  ASN1_INTEGER           = 0x02;
const CKYByte  ASN1_BIT_STRING        = 0x03;
const CKYByte  ASN1_OCTET_STRING      = 0x04;
const CKYByte  ASN1_ENUMERATED        = 0x0a;
const CKYByte  ASN1_UTF8_STRING       = 0x0c;
const CKYByte  ASN1_GENERALIZED_TIME  = 0x18;
const CKYByte  ASN1_CONSTRUCTED       = 0x20;
const CKYByte  ASN1_SEQUENCE          = 0x30;
const CKYByte  ASN1_CHOICE_0          = 0xa0;
const CKYByte  ASN1_CHOICE_1          = 0xa1;
const CKYByte  ASN1_CHOICE_2          = 0xa2;
const CKYByte  ASN1_CHOICE_3          = 0xa3;

const CKYBitFlags BROKEN_FLAG = 0x80000000;
const unsigned int PK11_INVALID_KEY_REF = -1;

const CKYByte PK15X509CertType = ASN1_SEQUENCE;
const CKYByte PK15RSAKeyType   = ASN1_SEQUENCE;
const CKYByte PK15ECCKeyType   = ASN1_CHOICE_0;
const CKYByte PK15DHKeyType    = ASN1_CHOICE_1;
const CKYByte PK15DSAKeyType   = ASN1_CHOICE_2;
const CKYByte PK15KEAKeyType   = ASN1_CHOICE_3;

class PKCS11Attribute {
  private:
    CK_ATTRIBUTE_TYPE type;
    CKYBuffer value;

  public:
    const CKYBuffer *getValue() const { return &value; }
    CK_ATTRIBUTE_TYPE getType() const {return type; }
    void setValue(const CKYByte *data, CKYSize size) {
	CKYBuffer_Replace(&value, 0, data, size);
    }
    void setType(CK_ATTRIBUTE_TYPE type_) { type = type_; }
    PKCS11Attribute(const PKCS11Attribute &cpy) {
	type = cpy.type;
	CKYBuffer_InitFromCopy(&value, &cpy.value);
    }
    PKCS11Attribute &operator=(PKCS11Attribute &cpy) {
	type = cpy.type;
	CKYBuffer_Replace(&value, 0, CKYBuffer_Data(&cpy.value),
				CKYBuffer_Size(&cpy.value));
	return *this;
    }
    PKCS11Attribute() : type(0){ CKYBuffer_InitEmpty(&value); }
    PKCS11Attribute(CK_ATTRIBUTE_TYPE type_, const CKYBuffer *value_)
        : type(type_) { CKYBuffer_InitFromCopy(&value, value_); }
    PKCS11Attribute(CK_ATTRIBUTE_TYPE type_, const CKYByte *data_,
	 CKYSize size_) : type(type_) 
		{ CKYBuffer_InitFromData(&value, data_, size_); }
    ~PKCS11Attribute() { CKYBuffer_FreeData(&value); }
};

class PK15ObjectPath {
  private:
    CKYBuffer path;
    CKYOffset index;
    CKYSize   length;
   public:
    PK15ObjectPath() : index(0), length(0) { CKYBuffer_InitEmpty(&path); }
    PK15ObjectPath(const PK15ObjectPath &cpy) : 
		index(cpy.index), length(cpy.length) 
		{ CKYBuffer_InitFromCopy(&path, &cpy.path); }
    ~PK15ObjectPath() { CKYBuffer_FreeData(&path); }
    const CKYBuffer *getPath() const { return &path; }
    CKYOffset getIndex() const { return index; }
    CKYSize getLength() const { return length; }
    CKYStatus setObjectPath(const CKYByte *entry, CKYSize size);
};


class PKCS11Object {
  public:
    enum KeyType {
        rsa,
        ecc,
        unknown
    };

    typedef list<PKCS11Attribute> AttributeList;
    typedef AttributeList::iterator AttributeIter;
    typedef AttributeList::const_iterator AttributeConstIter;

  private:
    AttributeList attributes;
    unsigned long muscleObjID;
    CK_OBJECT_HANDLE handle;
    char *label;
    unsigned int keySize;
    CK_USER_TYPE user;

    void parseOldObject(const CKYBuffer *data);
    void parseNewObject(const CKYBuffer *data);
    void expandAttributes(unsigned long fixedAttrs);

    PKCS11Object &operator=(PKCS11Object &cpy) { return *this; } //Disallow

  protected :
    char *name;
    KeyType keyType;
    unsigned int keyRef;
    CKYBuffer pubKey; 
    CKYBuffer authId;
    CKYBuffer pinAuthId;
    PK15ObjectPath objectPath;

  public:
    PKCS11Object(unsigned long muscleObjID, CK_OBJECT_HANDLE handle);
    PKCS11Object(unsigned long muscleObjID, const CKYBuffer *data,
        CK_OBJECT_HANDLE handle);
    ~PKCS11Object() { delete [] label; delete [] name; 
			CKYBuffer_FreeData(&pubKey);
			CKYBuffer_FreeData(&authId);
			CKYBuffer_FreeData(&pinAuthId); attributes.clear(); }

    PKCS11Object(const PKCS11Object& cpy) :
        attributes(cpy.attributes), muscleObjID(cpy.muscleObjID),
        handle(cpy.handle), label(NULL),  keySize(cpy.keySize),
	name(NULL), keyType(cpy.keyType), keyRef(cpy.keyRef),
	objectPath(cpy.objectPath) { 
			/* label is just a cached value, don't need
			 *  copy it. */
			if (cpy.name != NULL) {
			    int len = strlen(cpy.name);
			    name = new char [len+1];
			    if (name) {
				memcpy(name,cpy.name,len+1);
			    }
			}
			CKYBuffer_InitFromCopy(&pubKey,&cpy.pubKey);
			CKYBuffer_InitFromCopy(&authId,&cpy.authId);
			CKYBuffer_InitFromCopy(&pinAuthId,&cpy.pinAuthId); }

    unsigned long getMuscleObjID() const { return muscleObjID; }
    const CK_OBJECT_HANDLE getHandle() const { return handle; }

    /* PKCS11Attribute* getAttribute(CK_ATTRIBUTE_TYPE type); */
    const char *getLabel();
    CK_OBJECT_CLASS getClass();
    const char *getName() { return name; }

    void setAttribute(CK_ATTRIBUTE_TYPE type, const CKYBuffer *value);
    void setAttribute(CK_ATTRIBUTE_TYPE type, const char *);
    void setAttribute(CK_ATTRIBUTE_TYPE type, const CKYByte *data, 
							CKYSize size);
    /* bools and ulongs are too close, don't abuse function overloading
     * for these cases */
    void setAttributeBool(CK_ATTRIBUTE_TYPE type, CK_BBOOL);
    void setAttributeULong(CK_ATTRIBUTE_TYPE type, CK_ULONG);

    void removeAttribute(CK_ATTRIBUTE_TYPE type);

    bool matchesTemplate(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count) const;

    const CKYBuffer *getAttribute(CK_ATTRIBUTE_TYPE type) const;
    void getAttributeValue(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
        Log* log) const;
    bool attributeExists(CK_ATTRIBUTE_TYPE type) const;
    const CKYBuffer *getPubKey(void) const {
	return &pubKey;
    }

    KeyType getKeyType(void) const { return keyType;}
    unsigned int getKeySize(void) const { return keySize; }
    unsigned int getKeyRef(void) const { return keyRef; }
    CK_USER_TYPE getUser(void) const { return user; }
    void setKeyType(KeyType theType) { keyType = theType; }
    void setKeySize(unsigned int keySize_) { keySize = keySize_; }
    const CKYBuffer *getAuthId(void) const { return &authId; }
    const CKYBuffer *getPinAuthId(void) const { return &pinAuthId; }
    const PK15ObjectPath &getObjectPath() const { return objectPath; }
    void completeKey(const PKCS11Object &cert);
};

class Key : public PKCS11Object {
  public:
    Key(unsigned long muscleObjID, const CKYBuffer *data, CK_OBJECT_HANDLE handle);
};

class Cert : public PKCS11Object {
  public:
    Cert(unsigned long muscleObjID, const CKYBuffer *data,
        CK_OBJECT_HANDLE handle, const CKYBuffer *derCert);
};

class CACPrivKey : public PKCS11Object {
  public:
    CACPrivKey(CKYByte instance, const PKCS11Object &cert);
};

class CACPubKey : public PKCS11Object {
  public:
    CACPubKey(CKYByte instance, const PKCS11Object &cert);
};

class CACCert : public PKCS11Object {
  public:
    CACCert(CKYByte instance, const CKYBuffer *derCert);
};

typedef enum { PK15StateInit, PK15StateNeedObject, 
	PK15StateNeedRawPublicKey,PK15StateNeedRawCertificate, 
	PK15StateComplete } PK15State;

typedef enum {PK15PvKey, PK15PuKey, PK15Cert, PK15AuthObj} PK15ObjectType;
const unsigned int PK15_INVALID_KEY_REF = -1;

class PK15Object : public PKCS11Object {
  private:
    CKYByte	instance;
    PK15ObjectType p15Type;
    PK15State state;
    P15PinInfo pinInfo;

    CKYStatus completeCertObject(const CKYByte *buf, CKYSize size);
    CKYStatus completeAuthObject(const CKYByte *buf, CKYSize size);
    CKYStatus completeKeyObject(const CKYByte *buf, CKYSize size);
    CKYStatus completePrivKeyObject(const CKYByte *buf, CKYSize size);
    CKYStatus completePubKeyObject(const CKYByte *buf, CKYSize size);
    CKYStatus completeRawPublicKey(const CKYByte *buf, CKYSize size);
    CKYStatus completeRawCertificate(const CKYByte *buf, CKYSize size);
   
    CKYBitFlags defaultCommonBits() {
	return ((p15Type == PK15PvKey) && (CKYBuffer_Size(&authId) != 0)) ?
		P15FlagsPrivate : 0;
    }
    CKYBitFlags defaultUsageBits() {
	CKYBitFlags sign, recover, encrypt;
	switch (p15Type) {
	case PK15PuKey:
	    sign = P15UsageVerify; recover = P15UsageVerifyRecover;
	    encrypt = P15UsageEncrypt;
	    break;
	case PK15PvKey:
	    sign = P15UsageSign; recover = P15UsageSignRecover;
	    encrypt = P15UsageDecrypt;
	    break;
	default:
	    sign = 0; recover = 0; encrypt = 0;
	    break;
	}
	switch(keyType) {
	case rsa:
	    return sign | recover | encrypt;
	case ecc:
	    return sign | P15UsageDerive;
	default:
	    break;
	}
	return 0;
    }
    CKYBitFlags defaultAccessBits() {
	switch (p15Type) {
	case PK15PuKey:
		return P15AccessExtractable | P15AccessLocal;
	case PK15PvKey:
		return P15AccessSensitive | P15AccessLocal;
	default:
		break;
	}
	return 0;
    }
    CKYBitFlags defaultPinBits() {
	return ((p15Type == PK15AuthObj) ?  P15PinInitialized : 0);
    }
		
  public:
    PK15Object(CKYByte inst, PK15ObjectType type, 
					const CKYByte *derObject, CKYSize size);
    CKYStatus completeObject(const CKYByte *data, CKYSize size);
    PK15State getState(void) const { return state; }
    bool isSO(void) const { return 
		(pinInfo.pinFlags & P15PinSOPin) ? true : false; }
    bool isLocal(void) const { return 
			(pinInfo.pinFlags & P15PinLocal) ? true : false; }
    const P15PinInfo *getPinInfo(void) const { return &pinInfo; }
};

class Reader : public PKCS11Object {
  public:
    Reader(unsigned long muscleObjID, CK_OBJECT_HANDLE handle, 
		const char *reader, const CKYBuffer *cardATR, bool isCoolkey);
};

class SecretKey : public PKCS11Object {
    public: 
      SecretKey(unsigned long muscleObjID, CK_OBJECT_HANDLE handle, CKYBuffer *secretKeyBuffer, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount);
    private:
      void adjustToKeyValueLength(CKYBuffer * secretKeyBuffer,CK_ULONG valueLength);

};

class DEREncodedSignature  {

  protected :
    CKYBuffer derEncodedSignature;
  public:
    DEREncodedSignature(const CKYBuffer *derSig);
    ~DEREncodedSignature();
    int getRawSignature(CKYBuffer *rawSig, unsigned int keySize);

};

class DEREncodedTokenInfo {
public:
   int   version;
   CKYBuffer serialNumber;
   char *manufacturer;
   char *tokenName;
   public :
   DEREncodedTokenInfo(CKYBuffer *derTokenInfo);
   ~DEREncodedTokenInfo() { 
	CKYBuffer_FreeData(&serialNumber);
	free(manufacturer);
	free(tokenName);
    }
};

class AttributeMatch {

  private:
    const CK_ATTRIBUTE *attr;
  public:
    AttributeMatch( const CK_ATTRIBUTE *attr_) : attr(attr_) { }

    bool operator()(const PKCS11Attribute& cmp);
};

inline unsigned int
makeLEUInt(const CKYBuffer *buf, unsigned int offset)
{
    /* assert( offset + 4 <= CKYBuffer_Size(buf) ); */
    const CKYByte *b = CKYBuffer_Data(buf);

    return  (b[offset+3] << 24) |
            (b[offset+2] << 16) |
            (b[offset+1] <<  8) |
            (b[offset+0] <<  0) ;
}

const CKYByte* dataStart(const CKYByte *buf, CKYSize length,
                        CKYSize *data_length, bool includeTag);

// fixed object ID constants 
#define READER_ID 0x72300000 /* 'r0\0\0' */
#define COMBINED_ID 0x7a300000 /* 'z0\0\0' */

const CKYByte COMP_NONE=0;
const CKYByte COMP_ZLIB=1;
const CKYByte DATATYPE_STRING=0;
const CKYByte DATATYPE_INTEGER=1;
const CKYByte DATATYPE_BOOL_FALSE=2;
const CKYByte DATATYPE_BOOL_TRUE=3;

// relative to the header
const CKYOffset OBJ_FORMAT_VERSION_OFFSET = 0;
const CKYOffset OBJ_OBJECT_VERSION_OFFSET = 2;
const CKYOffset OBJ_CUID_OFFSET = 4;
const CKYSize OBJ_CUID_SIZE = 10;
const CKYOffset OBJ_COMP_TYPE_OFFSET = 14;
const CKYOffset OBJ_COMP_SIZE_OFFSET = 16;
const CKYOffset OBJ_COMP_OFFSET_OFFSET = 18;
const CKYSize OBJ_HEADER_SIZE = 20;

// relative to the start of the decompressed block 
const CKYOffset OBJ_OBJECT_OFFSET_OFFSET = 0;
const CKYOffset OBJ_OBJECT_COUNT_OFFSET = 2;
const CKYOffset OBJ_TOKENNAME_SIZE_OFFSET = 4;
const CKYOffset OBJ_TOKENNAME_OFFSET = 5;

#endif
