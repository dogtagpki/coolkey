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
    PKCS11Attribute() { CKYBuffer_InitEmpty(&value); }
    PKCS11Attribute(CK_ATTRIBUTE_TYPE type_, const CKYBuffer *value_)
        : type(type_) { CKYBuffer_InitFromCopy(&value, value_); }
    ~PKCS11Attribute() { CKYBuffer_FreeData(&value); }
};

class PKCS11Object {
  public:

    typedef list<PKCS11Attribute> AttributeList;
    typedef AttributeList::iterator AttributeIter;
    typedef AttributeList::const_iterator AttributeConstIter;

  private:
    AttributeList attributes;
    unsigned long muscleObjID;
    CK_OBJECT_HANDLE handle;
    char *label;

    void parseOldObject(const CKYBuffer *data);
    void parseNewObject(const CKYBuffer *data);
    void expandAttributes(unsigned long fixedAttrs);

    PKCS11Object &operator=(PKCS11Object &cpy) { return *this; } //Disallow

  protected :
    CKYBuffer pubKey; 
    char *name;

  public:
    PKCS11Object(unsigned long muscleObjID, CK_OBJECT_HANDLE handle);
    PKCS11Object(unsigned long muscleObjID, const CKYBuffer *data,
        CK_OBJECT_HANDLE handle);
    ~PKCS11Object() { delete label; delete name; CKYBuffer_FreeData(&pubKey); }

    PKCS11Object(const PKCS11Object& cpy) :
        attributes(cpy.attributes), muscleObjID(cpy.muscleObjID),
        handle(cpy.handle), label(NULL),  name(NULL) { 
			CKYBuffer_InitFromCopy(&pubKey,&cpy.pubKey); }


    unsigned long getMuscleObjID() const { return muscleObjID; }
    const CK_OBJECT_HANDLE getHandle() const { return handle; }

    /* PKCS11Attribute* getAttribute(CK_ATTRIBUTE_TYPE type); */
    const char *getLabel();
    CK_OBJECT_CLASS getClass();
    const char *getName() { return name; }

    void setAttribute(CK_ATTRIBUTE_TYPE type, const CKYBuffer *value);
    void setAttribute(CK_ATTRIBUTE_TYPE type, const char *);
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
};

class Key : public PKCS11Object {

  public:
    Key(unsigned long muscleObjID, const CKYBuffer *data, CK_OBJECT_HANDLE handle);
    void completeKey(const PKCS11Object &cert);
	
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

class Reader : public PKCS11Object {
  public:
    Reader(unsigned long muscleObjID, CK_OBJECT_HANDLE handle, 
		const char *reader, const CKYBuffer *cardATR, bool isCoolkey);
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
