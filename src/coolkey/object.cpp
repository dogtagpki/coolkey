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
#include "PKCS11Exception.h"
#include <algorithm>
#include <string.h>
#include "object.h"

using std::find_if;

const CKYByte rsaOID[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D, 0x01, 0x01,0x1};
const CKYByte eccOID[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};

#ifdef DEBUG
void dump(const char *label, const CKYBuffer *buf)
{
    CKYSize i;
    CKYSize size = CKYBuffer_Size(buf);
#define ROW_LENGTH 60
    char string[ROW_LENGTH+1];
    char *bp = &string[0];
    CKYByte c;

    printf("%s size=%d\n", label, (int)size);

    for (i=0; i < size; i++) {
	if (i && ((i % (ROW_LENGTH)) == 0) ) {
	    *bp = 0;
	    printf(" %s\n",string);
	    bp = &string[0];
	}
	c = CKYBuffer_GetChar(buf, i);
	printf("%02x ",c);
	*bp++ =  (c < ' ') ? '.' : ((c & 0x80) ? '*' : c);
    }
    *bp = 0;
    for (i= (i % (ROW_LENGTH)); i && (i < ROW_LENGTH); i++) {
	printf("   ");
    }
    printf(" %s\n",string);
    fflush(stdout);
}

void dumpData(const char *label, const CKYByte *buf, CKYSize size)
{
    CKYSize i;
#define ROW_LENGTH 16
    char string[ROW_LENGTH+1];
    char *bp = &string[0];
    CKYByte c;

    printf("%s size=%d:\n",label, (int)size);

    for (i=0; i < size; i++) {
	if (i && ((i % (ROW_LENGTH)) == 0) ) {
	    *bp = 0;
	    printf(" %s\n",string);
	    bp = &string[0];
	}
	c = buf[i];
	printf("%02x ",c);
	*bp++ =  (c < ' ') ? '.' : ((c & 0x80) ? '*' : c);
    }
    *bp = 0;
    for (i= (i % (ROW_LENGTH)); i && (i < ROW_LENGTH); i++) {
	printf("   ");
    }
    printf(" %s\n",string);
    fflush(stdout);
}
#endif

bool AttributeMatch::operator()(const PKCS11Attribute& cmp) 
{
    return (attr->type == cmp.getType()) &&
	CKYBuffer_DataIsEqual(cmp.getValue(), 
			(const CKYByte *)attr->pValue, attr->ulValueLen);
}

class AttributeTypeMatch
{
  private:
    CK_ATTRIBUTE_TYPE type;
  public:
    AttributeTypeMatch(CK_ATTRIBUTE_TYPE type_) : type(type_) { }
    bool operator()(const PKCS11Attribute& cmp) {
        return cmp.getType() == type;
    }
};

PKCS11Object::PKCS11Object(unsigned long muscleObjID_,CK_OBJECT_HANDLE handle_)
    : muscleObjID(muscleObjID_), handle(handle_), label(NULL), keySize(0),
	user(CKU_USER), name(NULL), keyType(unknown),
	keyRef(PK15_INVALID_KEY_REF)
{ 
    CKYBuffer_InitEmpty(&pubKey);
    CKYBuffer_InitEmpty(&authId);
    CKYBuffer_InitEmpty(&pinAuthId);
}

PKCS11Object::PKCS11Object(unsigned long muscleObjID_, const CKYBuffer *data,
    CK_OBJECT_HANDLE handle_) :  muscleObjID(muscleObjID_), handle(handle_),
			label(NULL), keySize(0), user(CKU_USER), name(NULL), 
			keyType(unknown), keyRef(PK15_INVALID_KEY_REF)
{
    CKYBuffer_InitEmpty(&pubKey);
    CKYBuffer_InitEmpty(&authId);
    CKYBuffer_InitEmpty(&pinAuthId);

    CKYByte type = CKYBuffer_GetChar(data,0);
    // verify object ID is what we think it is
    if( CKYBuffer_GetLong(data,1) != muscleObjID  ) {
        throw PKCS11Exception(CKR_DEVICE_ERROR, 
            "PKCS #11 actual object id does not match stated id");
    }
    if (type == 0) {
        parseOldObject(data);
    } else if (type == 1) {
        parseNewObject(data);
    }
}

SecretKey::SecretKey(unsigned long muscleObjID_, CK_OBJECT_HANDLE handle_, CKYBuffer *secretKeyBuffer, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount)
     : PKCS11Object(muscleObjID_, handle_)
{
    static CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    static CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    static CK_BBOOL value = 0x1;

    if ( secretKeyBuffer == NULL)
        return;

    /* Rifle through the input template */

    CK_ATTRIBUTE_TYPE type;
    CK_ATTRIBUTE attr;
    CK_ULONG valueLength = 0;

    for(int i = 0; i <  (int) ulAttributeCount; i++) {
       attr = pTemplate[i];
       type =  attr.type;

       if ( type == CKA_VALUE_LEN) {
           //CK_ULONG ulValueLen = attr.ulValueLen;
           valueLength = *((CK_ULONG *)attr.pValue);
       } else {

           CKYBuffer val;
           CKYBuffer_InitFromData(&val,(const CK_BYTE *) attr.pValue, attr.ulValueLen);
           setAttribute( type, &val);
           CKYBuffer_FreeData(&val);
       }
    }

    adjustToKeyValueLength( secretKeyBuffer, valueLength ); 

    /* Fall backs. */

    if(!attributeExists(CKA_CLASS))
        setAttributeULong(CKA_CLASS, objClass);

    if(!attributeExists(CKA_KEY_TYPE))
        setAttributeULong(CKA_KEY_TYPE, keyType);

    if(!attributeExists(CKA_TOKEN))
        setAttributeBool(CKA_TOKEN, value);
      
    if(!attributeExists(CKA_DERIVE)) 
        setAttributeBool(CKA_DERIVE, value);

    /* Actual value */
    setAttribute(CKA_VALUE, secretKeyBuffer);

}

void SecretKey::adjustToKeyValueLength(CKYBuffer * secretKeyBuffer,CK_ULONG valueLength)
{
    const CK_LONG MAX_DIFF = 200; /* Put some bounds on this value */

    if ( !secretKeyBuffer ) {
        return;
    }

    CKYBuffer scratch;
    CK_ULONG actual_length = CKYBuffer_Size(secretKeyBuffer);

    CK_LONG diff = 0;
    diff = (CK_LONG) valueLength - actual_length;

    if ( diff == 0 ) {
        return;
    }

    if ( diff > 0 && diff < MAX_DIFF ) { /*check for silly values */
        /* prepend with zeroes */
        CKYBuffer_InitFromLen(&scratch, diff);
        CKYBuffer_AppendCopy(&scratch, secretKeyBuffer);

        CKYBuffer_FreeData(secretKeyBuffer);
        CKYBuffer_InitFromCopy(secretKeyBuffer, &scratch);
        CKYBuffer_FreeData(&scratch);

    } else if (diff < 0 ) {
        /* truncate most significant bytes */
        CKYBuffer_InitFromData(&scratch, CKYBuffer_Data(secretKeyBuffer)-diff, valueLength);
        CKYBuffer_FreeData(secretKeyBuffer);
        CKYBuffer_InitFromCopy(secretKeyBuffer, &scratch);
        CKYBuffer_FreeData(&scratch);
    }
}

void
PKCS11Object::parseOldObject(const CKYBuffer *data)
{
    if( CKYBuffer_Size(data) < 7 ) {
        throw PKCS11Exception(CKR_DEVICE_ERROR,
            "Invalid PKCS#11 object size %d", CKYBuffer_Size(data));
    }

    // get the amount of attribute data, make sure it makes sense
    unsigned int attrDataLen = CKYBuffer_GetShort(data, 5);
    if( CKYBuffer_Size(data) != attrDataLen + 7 ) {
        throw PKCS11Exception(CKR_DEVICE_ERROR,
            "PKCS #11 actual attribute data length %d does not match"
            " stated length %d", CKYBuffer_Size(data)-7, attrDataLen);
    }

    unsigned int idx = 7;
    while( idx < CKYBuffer_Size(data) ) {
        if( idx - CKYBuffer_Size(data) < 6 ) {
            throw PKCS11Exception(CKR_DEVICE_ERROR,
                "Error parsing attribute");
        }
        PKCS11Attribute attrib;
        attrib.setType(CKYBuffer_GetLong(data, idx));
        idx += 4;
        unsigned int attrLen = CKYBuffer_GetShort(data, idx);
                idx += 2;
        if( attrLen > CKYBuffer_Size(data) 
                        || (idx + attrLen > CKYBuffer_Size(data)) ) {
            throw PKCS11Exception(CKR_DEVICE_ERROR,
                "Invalid attribute length %d\n", attrLen);
        }
        /* these two types are ints, read them back from 
         * the card in host order */
        if ((attrib.getType() == CKA_CLASS) || 
            (attrib.getType() == CKA_CERTIFICATE_TYPE) ||
            (attrib.getType() == CKA_KEY_TYPE)) {
            /* ulongs are 4 bytes on the token, even if they are 8 or
             * more in the pkcs11 module */
            if (attrLen != 4) {
                throw PKCS11Exception(CKR_DEVICE_ERROR,
                "Invalid attribute length %d\n", attrLen);
            }
            CK_ULONG value = makeLEUInt(data,idx);

            attrib.setValue((const CKYByte *)&value, sizeof(CK_ULONG));
        } else {
            attrib.setValue(CKYBuffer_Data(data)+idx, attrLen);
        }
        idx += attrLen;
        attributes.push_back(attrib);
    }

}

//
// masks which determine the valid flag bits for specific objects
//
//  objects are :                       flags are:
//    0 CKO_DATA                          PRIVATE, MODIFIABLE, TOKEN
//    1 CKO_CERTIFICATE                   PRIVATE, MODIFIABLE, TOKEN
//    2 CKO_PUBLIC_KEY                    PRIVATE, MODIFIABLE, TOKEN
//                                        DERIVE, LOCAL, ENCRYPT, WRAP
//                                        VERIFY, VERIFY_RECOVER
//    3 CKO_PRIVATE_KEY                   PRIVATE, MODIFIABLE, TOKEN
//                                        DERIVE, LOCAL, DECRYPT, UNWRAP
//                                        SIGN, SIGN_RECOVER, SENSITIVE,
//                                        ALWAYS_SENSITIVE, EXTRACTABLE,
//                                        NEVER_EXTRACTABLE
//    4 CKO_SECRET_KEY                    PRIVATE, MODIFIABLE, TOKEN
//                                        DERIVE, LOCAL, ENCRYPT, DECRYPT,
//                                        WRAP, UNWRAP, SIGN, VERIFY,
//                                        SENSITIVE, ALWAYS_SENSITIVE,
//                                        EXTRACTABLE, NEVER_EXTRACTABLE
//    5-7 RESERVED                        NONE
//
const unsigned long boolMask[8] =
{
    0x00000380, 0x00000380,
    0x000c5f80, 0x00f3af80,
    0x00f5ff80, 0x00000000,
    0x00000000, 0x00000000
};

//
// map a mask bit position to CKA_ flag value.
//
const CK_ATTRIBUTE_TYPE boolType[32] =
{
    0, 0, 0, 0,
    0, 0, 0, CKA_TOKEN,
    CKA_PRIVATE, CKA_MODIFIABLE, CKA_DERIVE, CKA_LOCAL,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP,
    CKA_SIGN, CKA_SIGN_RECOVER, CKA_VERIFY, CKA_VERIFY_RECOVER, 
    CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE, CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE,
    0, 0, 0, 0,
    0, 0, 0, 0,
};

void
PKCS11Object::expandAttributes(unsigned long fixedAttrs)
{
    CKYByte cka_id = (CKYByte) (fixedAttrs & 0xf);
    CK_OBJECT_CLASS objectType = (fixedAttrs >> 4) & 0x7;
    unsigned long mask = boolMask[objectType];
    unsigned long i;

    if (!attributeExists(CKA_ID)) {
        PKCS11Attribute attrib;
        attrib.setType(CKA_ID);
        attrib.setValue(&cka_id, 1);
        attributes.push_back(attrib);
    }
    /* unpack the class */
    if (!attributeExists(CKA_CLASS)) {
        PKCS11Attribute attrib;
        attrib.setType(CKA_CLASS);
        attrib.setValue((CKYByte *)&objectType, sizeof(CK_ULONG));
        attributes.push_back(attrib);
    }

    /* unpack the boolean flags. Note, the default mask is based on
     * the class specified in fixedAttrs, not on the real class */
    for (i=1; i < sizeof(unsigned long)*8; i++) {
        unsigned long iMask = 1<< i;
        if ((mask & iMask) == 0) {
           continue;
        }
        if (attributeExists(boolType[i])) {
            continue;
        }
        PKCS11Attribute attrib;
        CKYByte bVal = (fixedAttrs & iMask) != 0;
        attrib.setType(boolType[i]);
        attrib.setValue(&bVal, 1);
        attributes.push_back(attrib);
    }
}

void
PKCS11Object::parseNewObject(const CKYBuffer *data)
{
    if( CKYBuffer_Size(data) < 11 ) {
        throw PKCS11Exception(CKR_DEVICE_ERROR,
            "Invalid PKCS#11 object size %d", CKYBuffer_Size(data));
    }
    unsigned short attributeCount = CKYBuffer_GetShort(data, 9);
    unsigned long fixedAttrs = CKYBuffer_GetLong(data, 5);
    unsigned long offset = 11;
    CKYSize size = CKYBuffer_Size(data);
    int j;

    // load up the explicit attributes first
    for (j=0, offset = 11; j < attributeCount && offset < size; j++) {
        PKCS11Attribute attrib;
        CKYByte attributeDataType = CKYBuffer_GetChar(data, offset+4);
        unsigned int attrLen = 0;
        attrib.setType(CKYBuffer_GetLong(data, offset));
        offset += 5;

        switch(attributeDataType) {
        case DATATYPE_STRING:
            attrLen = CKYBuffer_GetShort(data, offset);
            offset += 2;
            if (attrLen > CKYBuffer_Size(data) 
                        || (offset + attrLen > CKYBuffer_Size(data)) ) {
                    throw PKCS11Exception(CKR_DEVICE_ERROR,
                        "Invalid attribute length %d\n", attrLen);
             }
            attrib.setValue(CKYBuffer_Data(data)+offset, attrLen);
            break;
        case DATATYPE_BOOL_FALSE:
        case DATATYPE_BOOL_TRUE:
            {
                CKYByte bval = attributeDataType & 1;
                attrib.setValue(&bval, 1);
            }
            break;
        case DATATYPE_INTEGER:
            {
                CK_ULONG value = CKYBuffer_GetLong(data, offset);
                attrLen = 4;
                attrib.setValue((const CKYByte *)&value, sizeof(CK_ULONG));
            }
            break;
        default:
            throw PKCS11Exception(CKR_DEVICE_ERROR, 
                "Invalid attribute Data Type %d\n", attributeDataType);
        }
        offset += attrLen;
        attributes.push_back(attrib);
    }
    expandAttributes(fixedAttrs);
}

#if defined( NSS_HIDE_NONSTANDARD_OBJECTS )

static const CK_OBJECT_CLASS rdr_class = CKO_MOZ_READER;
static const CK_BBOOL        rdr_true  = TRUE;
static const CK_ATTRIBUTE    rdr_template[] = {
    {CKA_CLASS,          (void *)&rdr_class, sizeof rdr_class },
    {CKA_MOZ_IS_COOL_KEY, (void *)&rdr_true,  sizeof rdr_true  }
};
#endif

bool
PKCS11Object::matchesTemplate(const CK_ATTRIBUTE_PTR pTemplate, 
                                                CK_ULONG ulCount)
    const
{
    unsigned int i;

    typedef std::list<PKCS11Attribute>::const_iterator iterator;

#if defined( NSS_HIDE_NONSTANDARD_OBJECTS )
    if (!ulCount) {
        // exclude MOZ reader objects from searches for all objects.
        // To find an MOZ reader object, one must search for it by 
        // some matching attribute, such as class.
        iterator iter = find_if(attributes.begin(), attributes.end(),
                                AttributeMatch(&rdr_template[0]));
        return (iter == attributes.end()) ? true : false;
    }
#endif

    // loop over all attributes in the template
    for( i = 0; i < ulCount; ++i ) {
        // lookup this attribute in our object
        iterator iter = find_if(attributes.begin(), attributes.end(),
            AttributeMatch(pTemplate+i));
        if( iter == attributes.end() ) {
            // attribute not found. Template does not match.
            return false;
        }
    }

    // all attributes found. template matches.
    return true;
}

bool
PKCS11Object::attributeExists(CK_ATTRIBUTE_TYPE type) const
{
    // find matching attribute
    AttributeConstIter iter = find_if(attributes.begin(), attributes.end(),
            AttributeTypeMatch(type));
    return (bool)(iter != attributes.end()); 
}

const CKYBuffer *
PKCS11Object::getAttribute(CK_ATTRIBUTE_TYPE type) const
{
    AttributeConstIter iter = find_if(attributes.begin(), attributes.end(),
            AttributeTypeMatch(type));

    if( iter == attributes.end() ) {
        return NULL;
    }
    return iter->getValue();
}

void
PKCS11Object::getAttributeValue(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    Log* log) const
{
    // keep track if these error conditions are true for any attribute
    bool attrTypeInvalid = false;
    bool bufferTooSmall = false;

    unsigned int i;
    // loop over all attributes in the template
    for( i = 0; i < ulCount; ++i ) {

        // find matching attribute
        AttributeConstIter iter = find_if(attributes.begin(), attributes.end(),
            AttributeTypeMatch(pTemplate[i].type));

        if( iter == attributes.end() ) {
            // no attribute of this type
            attrTypeInvalid = true;
            if ( log )
                log->log("GetAttributeValue: invalid type 0x%08x on object %x\n",
                    pTemplate[i].type, muscleObjID);
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            continue;
        }

        if( pTemplate[i].pValue == NULL ) {
            // Buffer not supplied for this attribute. We just set the length.
            pTemplate[i].ulValueLen = CKYBuffer_Size(iter->getValue());
            continue;
        }
    
        if( pTemplate[i].ulValueLen < CKYBuffer_Size(iter->getValue()) ) {
            // supplied buffer is not large enough.
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            bufferTooSmall = true;
            continue;
        }

        // the buffer is large enough. return the value and set the exact
        // length.
        memcpy(pTemplate[i].pValue, CKYBuffer_Data(iter->getValue()), 
                                        CKYBuffer_Size(iter->getValue()));
        pTemplate[i].ulValueLen = CKYBuffer_Size(iter->getValue());
    }

    if( attrTypeInvalid ) {
        // At least one of the attribute types was invalid.
        // Return CKR_ATTRIBUTE_TYPE_INVALID. This is not really an
        // error condition.
        throw PKCS11Exception(CKR_ATTRIBUTE_TYPE_INVALID);
    }

    if( bufferTooSmall ) {
        // At least one of the supplied buffers was too small.
        // Return CKR_BUFFER_TOO_SMALL. This is not really an error
        // condition.
        throw PKCS11Exception(CKR_BUFFER_TOO_SMALL);
    }

    // no problems, just return CKR_OK
}

const char *
PKCS11Object::getLabel() 
{
    // clean up old one
    if (label) {
	delete [] label;
	label = NULL;
    }
    // find matching attribute
    AttributeConstIter iter = find_if(attributes.begin(), attributes.end(),
            AttributeTypeMatch(CKA_LABEL));

    // none found 
    if( iter == attributes.end() ) {
        return "";
    }

    int size = CKYBuffer_Size(iter->getValue());

    label = new char [ size + 1 ];
    if (!label) {
        return "";
    }
    memcpy(label, CKYBuffer_Data(iter->getValue()), size);
    label[size] = 0;

    return label;
}

CK_OBJECT_CLASS
PKCS11Object::getClass() 
{
    CK_OBJECT_CLASS objClass;
    // find matching attribute
    AttributeConstIter iter = find_if(attributes.begin(), attributes.end(),
            AttributeTypeMatch(CKA_CLASS));

    // none found */
    if( iter == attributes.end() ) {
        return (CK_OBJECT_CLASS) -1;
    }

    int size = CKYBuffer_Size(iter->getValue());

    if (size != sizeof(objClass)) {
        return (CK_OBJECT_CLASS) -1;
    }

    memcpy(&objClass, CKYBuffer_Data(iter->getValue()), size);

    return objClass;
}

void
PKCS11Object::setAttribute(CK_ATTRIBUTE_TYPE type, const CKYBuffer *value)
{
    AttributeIter iter;  

    iter = find_if(attributes.begin(), attributes.end(),
        AttributeTypeMatch(type));
    if( iter != attributes.end() )  {
        iter->setValue( CKYBuffer_Data(value), CKYBuffer_Size(value));
    } else {
        attributes.push_back(PKCS11Attribute(type, value));
    }
}

void
PKCS11Object::setAttribute(CK_ATTRIBUTE_TYPE type, const CKYByte *data,
			CKYSize size)
{
    AttributeIter iter;  

    iter = find_if(attributes.begin(), attributes.end(),
        AttributeTypeMatch(type));
    if( iter != attributes.end() )  {
        iter->setValue( data, size);
    } else {
        attributes.push_back(PKCS11Attribute(type, data, size));
    }
}

void
PKCS11Object::setAttribute(CK_ATTRIBUTE_TYPE type, const char *string)
{
    CKYBuffer buf;
    CKYBuffer_InitFromData(&buf, (const CKYByte *)string, strlen(string));

    setAttribute(type, &buf);
    CKYBuffer_FreeData(&buf);
}

void
PKCS11Object::setAttributeBool(CK_ATTRIBUTE_TYPE type, CK_BBOOL value)
{
    CKYBuffer buf;
    CKYBuffer_InitFromData(&buf, &value, sizeof(CK_BBOOL));

    setAttribute(type,&buf);
    CKYBuffer_FreeData(&buf);
}

void
PKCS11Object::setAttributeULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value)
{
    CKYBuffer buf;
    CKYBuffer_InitFromData(&buf, (const CKYByte *)&value, sizeof(CK_ULONG));

    setAttribute(type, &buf);
    CKYBuffer_FreeData(&buf);
}

typedef struct {
    const CKYByte*data;
    CKYSize len;
} CCItem;

typedef enum {
    SECSuccess=0,
    SECFailure=1
} SECStatus;

const CKYByte*
dataStart(const CKYByte *buf, CKYSize length,
                        CKYSize *data_length, bool includeTag) {
    unsigned char tag;
    unsigned int used_length= 0;

    *data_length = 0; /* make sure data_length is zero on failure */

    if(!buf) {
        return NULL;
    }
    /* there must be at least 2 bytes */
    if (length < 2) {
	return NULL;
    }

    tag = buf[used_length++];

    /* blow out when we come to the end */
    if (tag == 0) {
        return NULL;
    }

    *data_length = buf[used_length++];

    if (*data_length&0x80) {
        int  len_count = *data_length & 0x7f;

	if (len_count+used_length > length) {
	    return NULL;
	}

        *data_length = 0;

        while (len_count-- > 0) {
            *data_length = (*data_length << 8) | buf[used_length++];
        }
    }
    /* paranoia, can't happen */
    if (length < used_length) {
	return NULL;
    }

    if (*data_length > (length-used_length) ) {
        return NULL;
    }
    if (includeTag) *data_length += used_length;

    return (buf + (includeTag ? 0 : used_length));
}

static const CKYByte *
unwrapBitString(const CKYByte *buf, CKYSize len, CKYSize *retLen)
{
    /* for RSA, bit string always has byte number of bits */
    if (buf[0] != 0) {
	return NULL;
    }
    if (len < 1) {
	return NULL;
    }
    *retLen = len -1;
    return buf+1;
}

static SECStatus
GetECKeyFieldItems(const CKYByte *spki_data, CKYSize spki_length,
        CCItem *point, CCItem *params)
{
    const CKYByte *buf = spki_data;
    CKYSize buf_length = spki_length;
    const CKYByte*dummy;
    CKYSize dummylen;
    const CKYByte *algid;
    CKYSize algidlen;

    if (!point || !params || !buf)
        return SECFailure;

    point->data = NULL;
    point->len = 0;
    params->data = NULL;
    params->len = 0;

    /* unwrap the algorithm id */
    dummy = dataStart(buf,buf_length,&dummylen,false);
    if (dummy == NULL) return SECFailure;
    buf_length -= (dummy-buf) + dummylen;
    buf = dummy + dummylen;
    /* unwrpped value is in dummy */
    algid = dummy;
    algidlen = dummylen;
    /* skip past algid oid */
    dummy = dataStart(algid, algidlen, &dummylen, false);
    if (dummy == NULL) return SECFailure;
    algidlen -= (dummy-algid) + dummylen;
    algid = dummy + dummylen;
    params->data = algid;
    params->len = algidlen;

       /* unwrap the public key info */
    buf = dataStart(buf,buf_length,&buf_length,false);
    if (buf == NULL) return SECFailure;
    buf = unwrapBitString(buf,buf_length,&buf_length);
    if (buf == NULL) return SECFailure;

    point->data = buf;
    point->len = buf_length;

    if(point->data == NULL) return SECFailure;

    return SECSuccess;
}

static bool
GetKeyOIDMatches(const CKYByte *spki_data, unsigned int length, const CKYByte *oid_data)
{
    bool ret = TRUE;

    if( spki_data == NULL || oid_data == NULL) {
        return FALSE;
    }

    for ( int i = 0 ; i < (int) length ; i++) {
        if (spki_data[i] != oid_data[i]) {
            ret = FALSE;
            break;
        }
            
    }

    return ret;
}

static SECStatus
GetKeyAlgorithmId(const CKYByte *spki_data, CKYSize spki_length,
       CCItem *algorithmId)
{

    const CKYByte *buf = spki_data;
    CKYSize buf_length = spki_length;

    if ( algorithmId == NULL) return SECFailure;

    /* objtain the algorithm id */
    algorithmId->data = dataStart(buf,buf_length,&algorithmId->len,false);

    return SECSuccess;

}

static PKCS11Object::KeyType
GetKeyTypeFromSPKI(const CKYBuffer *key)
{
    CCItem algIdItem;
    SECStatus ret = GetKeyAlgorithmId(CKYBuffer_Data(key), 
                                      CKYBuffer_Size(key),&algIdItem);
    PKCS11Object::KeyType foundType = PKCS11Object::unknown;

    if ( ret != SECSuccess ) {
	throw PKCS11Exception(CKR_FUNCTION_FAILED,
	     "Failed to decode key algorithm ID.");
    }

    CKYSize length = 0;
    const CKYByte *keyData = NULL;

    /* Get actual oid buffer */

    keyData = dataStart(algIdItem.data,algIdItem.len,&length, false);
    if (keyData == NULL) {
	throw PKCS11Exception(CKR_FUNCTION_FAILED,
			"Failed to decode key algorithm ID.");
    }

    bool match = FALSE;
    
    /* Check for outrageous length */

    if ( length <= 3 || length >= algIdItem.len) {
	throw PKCS11Exception(CKR_FUNCTION_FAILED,
	     "Failed to decode key algorithm ID.");
    }
    /* check for RSA */
 
    match = GetKeyOIDMatches(keyData, length, rsaOID);
   
    if ( match == TRUE ) {
	foundType = PKCS11Object::rsa;
    } else { 
	/* check for ECC */
	match = GetKeyOIDMatches(keyData, length, eccOID);

	if ( match == TRUE ) {
            foundType = PKCS11Object::ecc;
	}

    }

    if ( foundType == PKCS11Object::unknown) {
	throw PKCS11Exception(CKR_FUNCTION_FAILED,
	     "Failed to decode key algorithm ID.");
    }
    return foundType;
}


static SECStatus
GetKeyFieldItems(const CKYByte *spki_data,CKYSize spki_length,
        CCItem *modulus, CCItem *exponent)
{
    const CKYByte *buf = spki_data;
    CKYSize buf_length = spki_length;
    const CKYByte*dummy;
    CKYSize dummylen;

    /* skip past the algorithm id */
    dummy = dataStart(buf,buf_length,&dummylen,false);
    if (dummy == NULL) return SECFailure;
    buf_length -= (dummy-buf) + dummylen;
    buf = dummy + dummylen;

    /* unwrap the public key info */
    buf = dataStart(buf,buf_length,&buf_length,false);
    if (buf == NULL) return SECFailure;
    buf = unwrapBitString(buf,buf_length,&buf_length);
    if (buf == NULL) return SECFailure;
    buf = dataStart(buf,buf_length,&buf_length, false);
    if (buf == NULL) return SECFailure;

    /* read the modulus */
    modulus->data = dataStart(buf,buf_length,&modulus->len,false);
    if (modulus->data == NULL) return SECFailure;
    buf_length -= (modulus->data-buf) + modulus->len;
    buf = modulus->data + modulus->len;

    /* read the exponent */
    exponent->data = dataStart(buf,buf_length,&exponent->len,false);
    if (exponent->data == NULL) return SECFailure;
    buf_length -= (exponent->data-buf) + exponent->len;
    buf = exponent->data + exponent->len;

    return SECSuccess;
}

static void
GetKeyFields(const CKYBuffer *spki, CKYBuffer *modulus, CKYBuffer *exponent)
{
    SECStatus rv;
    CCItem modulusItem, exponentItem;

    rv = GetKeyFieldItems(CKYBuffer_Data(spki), CKYBuffer_Size(spki), 
        &modulusItem, &exponentItem);

    if( rv != SECSuccess ) {
        throw PKCS11Exception(CKR_FUNCTION_FAILED,
            "Failed to decode certificate Subject Public Key Info");
    }

    CKYBuffer_Replace(modulus, 0, modulusItem.data, modulusItem.len);
    CKYBuffer_Replace(exponent, 0, exponentItem.data, exponentItem.len);
}

static void
GetECKeyFields(const CKYBuffer *spki, CKYBuffer *point, CKYBuffer *params)
{
    SECStatus rv;
    CCItem pointItem, paramsItem;

    if (spki == NULL || point == NULL || params == NULL) {
        throw PKCS11Exception(CKR_FUNCTION_FAILED,
             "Failed to decode certificate Subject Public KeyInfo!");
    }
    
    rv = GetECKeyFieldItems(CKYBuffer_Data(spki), CKYBuffer_Size(spki),
        &pointItem, &paramsItem);

    if( rv != SECSuccess ) {
        throw PKCS11Exception(CKR_FUNCTION_FAILED,
            "Failed to decode certificate Subject Public Key Info!");
    }

    CKYBuffer_Replace(point, 0, pointItem.data, pointItem.len);
    CKYBuffer_Replace(params, 0, paramsItem.data, paramsItem.len);
}

Key::Key(unsigned long muscleObjID, const CKYBuffer *data,
    CK_OBJECT_HANDLE handle) : PKCS11Object(muscleObjID, data, handle)
{
    // infer key attributes
    CK_OBJECT_CLASS objClass = getClass();
    CKYBuffer empty;
    CKYBuffer_InitEmpty(&empty);

    if ((objClass == CKO_PUBLIC_KEY) || (objClass == CKO_PRIVATE_KEY)) {
        //we may know already what type of key this is.
        if (attributeExists(CKA_KEY_TYPE)) {
            CK_ULONG type = 0;
            CK_ATTRIBUTE aTemplate = {CKA_KEY_TYPE, &type, sizeof(CK_ULONG)};
    
            getAttributeValue(&aTemplate, 1, NULL);

            if (type == 0x3) {
                setKeyType(ecc);
                setAttributeULong(CKA_KEY_TYPE, CKK_EC);
            } else {  
                setKeyType(rsa);
                setAttributeULong(CKA_KEY_TYPE, CKK_RSA);
            }
        } else {
           /* default to rsa */
           setKeyType(rsa);
           setAttributeULong(CKA_KEY_TYPE, CKK_RSA); 
        }

    // Could be RSA or ECC
    } else if (objClass == CKO_SECRET_KEY) {
	if (!attributeExists(CKA_LABEL)) {
	    setAttribute(CKA_LABEL, &empty);
	}
	if (!attributeExists(CKA_KEY_TYPE)) {
	    /* default to DES3 */
	    setAttributeULong(CKA_KEY_TYPE, CKK_DES3);
	}
    }
    if (!attributeExists(CKA_START_DATE)) {
	setAttribute(CKA_START_DATE, &empty);
    }
    if (!attributeExists(CKA_END_DATE)) {
	setAttribute(CKA_END_DATE, &empty);
    }
}

void
PKCS11Object::completeKey(const PKCS11Object &cert)
{
    // infer key attributes from cert
    bool modulusExists, exponentExists;
    bool pointExists, paramsExists;

    PKCS11Object::KeyType keyType;
    const CKYBuffer *key = cert.getPubKey();

    if (!attributeExists(CKA_LABEL)) {
	setAttribute(CKA_LABEL, cert.getAttribute(CKA_LABEL));
    }

    CKYBuffer param1; CKYBuffer_InitEmpty(&param1); 
    CKYBuffer param2; CKYBuffer_InitEmpty(&param2); 
    try {
	keyType = GetKeyTypeFromSPKI(key);
	setKeyType(keyType);

	switch (keyType) {
	case rsa:
            modulusExists = attributeExists(CKA_MODULUS);
	    exponentExists = attributeExists(CKA_PUBLIC_EXPONENT);
	    if (!modulusExists || !exponentExists) {
	        GetKeyFields(key, &param1, &param2);
	        if (!modulusExists) {
	    	    setAttribute(CKA_MODULUS, &param1);
	        }
	        if (!exponentExists) {
	  	    setAttribute(CKA_PUBLIC_EXPONENT, &param2);
	        }
	    }
	    break;
	case ecc:
            pointExists = attributeExists(CKA_EC_POINT);
            paramsExists = attributeExists(CKA_EC_PARAMS);

            if (!pointExists || !paramsExists) {
                GetECKeyFields(key, &param1, &param2);
                if (!pointExists) {
                   setAttribute(CKA_EC_POINT, &param1);
                }
                if (!paramsExists) {
                    setAttribute(CKA_EC_PARAMS, &param2);
                }
            }
	    break;
	default:
	    break;
	}
    } catch (PKCS11Exception &e) {
	CKYBuffer_FreeData(&param1);
	CKYBuffer_FreeData(&param2);
	throw e;
    }
    CKYBuffer_FreeData(&param1);
    CKYBuffer_FreeData(&param2);
}

static SECStatus
GetCertFieldItems(const CKYByte *dercert, CKYSize cert_length,
        CCItem *issuer, CCItem *serial, CCItem *derSN, CCItem *subject,
        CCItem *valid, CCItem *subjkey)
{
    const CKYByte *buf;
    CKYSize buf_length;
    const CKYByte*dummy;
    CKYSize dummylen;

    /* get past the signature wrap */
    buf = dataStart(dercert,cert_length,&buf_length, false);
    if (buf == NULL) return SECFailure;

    /* get into the raw cert data */
    buf = dataStart(buf,buf_length,&buf_length,false);
    if (buf == NULL) return SECFailure;

    /* skip past any optional version number */
    if ((buf[0] & 0xa0) == 0xa0) {
        dummy = dataStart(buf,buf_length,&dummylen,false);
        if (dummy == NULL) return SECFailure;
        buf_length -= (dummy-buf) + dummylen;
        buf = dummy + dummylen;
    }

    /* serial number */
    if (derSN) {
        derSN->data=dataStart(buf,buf_length,&derSN->len,true);
    }
    serial->data = dataStart(buf,buf_length,&serial->len,false);
    if (serial->data == NULL) return SECFailure;
    buf_length -= (serial->data-buf) + serial->len;
    buf = serial->data + serial->len;

    /* skip the OID */
    dummy = dataStart(buf,buf_length,&dummylen,false);
    if (dummy == NULL) return SECFailure;
    buf_length -= (dummy-buf) + dummylen;
    buf = dummy + dummylen;

    /* issuer */
    issuer->data = dataStart(buf,buf_length,&issuer->len,true);
    if (issuer->data == NULL) return SECFailure;
    buf_length -= (issuer->data-buf) + issuer->len;
    buf = issuer->data + issuer->len;

    /* validity */
    valid->data = dataStart(buf,buf_length,&valid->len,false);
    if (valid->data == NULL) return SECFailure;
    buf_length -= (valid->data-buf) + valid->len;
    buf = valid->data + valid->len;

    /*subject */
    subject->data=dataStart(buf,buf_length,&subject->len,true);
    if (subject->data == NULL) return SECFailure;
    buf_length -= (subject->data-buf) + subject->len;
    buf = subject->data + subject->len;

    /* subject  key info */
    subjkey->data=dataStart(buf,buf_length,&subjkey->len,false);
    if (subjkey->data == NULL) return SECFailure;
    buf_length -= (subjkey->data-buf) + subjkey->len;
    buf = subjkey->data + subjkey->len;
    return SECSuccess;
}

static void
GetCertFields(const CKYBuffer *derCert, CKYBuffer *derSerial, 
            CKYBuffer *derSubject, CKYBuffer *derIssuer, CKYBuffer *subjectKey)
{
    SECStatus rv;
    CCItem issuerItem, serialItem, derSerialItem, subjectItem,
        validityItem, subjectKeyItem;

    rv = GetCertFieldItems(CKYBuffer_Data(derCert), CKYBuffer_Size(derCert), 
        &issuerItem, &serialItem, &derSerialItem, &subjectItem, &validityItem,
        &subjectKeyItem);

    if( rv != SECSuccess ) {
        throw PKCS11Exception(CKR_FUNCTION_FAILED,
            "Failed to decode DER certificate");
    }

    CKYBuffer_Replace(derSerial, 0, derSerialItem.data, derSerialItem.len);
    CKYBuffer_Replace(derIssuer, 0, issuerItem.data, issuerItem.len);
    CKYBuffer_Replace(derSubject, 0, subjectItem.data, subjectItem.len);
    CKYBuffer_Replace(subjectKey, 0, subjectKeyItem.data, subjectKeyItem.len);
}

Cert::Cert(unsigned long muscleObjID, const CKYBuffer *data,
    CK_OBJECT_HANDLE handle, const CKYBuffer *derCert)
    : PKCS11Object(muscleObjID, data, handle)
{
    CKYBuffer derSerial; CKYBuffer_InitEmpty(&derSerial);
    CKYBuffer derSubject; CKYBuffer_InitEmpty(&derSubject);
    CKYBuffer derIssuer; CKYBuffer_InitEmpty(&derIssuer);
    CKYBuffer certType;
    CK_ULONG certTypeValue = CKC_X_509;

    CKYBuffer_InitFromData(&certType, (CKYByte *)&certTypeValue, 
                                                sizeof(certTypeValue));
    CKYBuffer_Resize(&pubKey,0);

    try {
         setAttribute(CKA_CERTIFICATE_TYPE, &certType);

        if (!attributeExists(CKA_VALUE)) {
            if (derCert) {
                 setAttribute(CKA_VALUE, derCert);
            } else  {
                throw PKCS11Exception(CKR_DEVICE_ERROR, 
                    "Missing certificate data from token");
            }
        }

        if (!derCert) {
            derCert = getAttribute(CKA_VALUE);
            if (!derCert) {
                // paranoia, should never happen since we verify the
                // attribute exists above
                throw PKCS11Exception(CKR_DEVICE_ERROR, 
                     "Missing certificate data from token");
            }
        }

        // infer cert attributes

        GetCertFields(derCert, &derSerial, &derSubject, &derIssuer, &pubKey);

        if (!attributeExists(CKA_SERIAL_NUMBER)) {
            setAttribute(CKA_SERIAL_NUMBER, &derSerial);
        }
        if (!attributeExists(CKA_SUBJECT)) {
            setAttribute(CKA_SUBJECT, &derSubject);
        }
        if (!attributeExists(CKA_ISSUER)) {
            setAttribute(CKA_ISSUER, &derIssuer);
        }
   } catch (PKCS11Exception &e) {
        CKYBuffer_FreeData(&certType);
        CKYBuffer_FreeData(&derSerial);
        CKYBuffer_FreeData(&derSubject);
        CKYBuffer_FreeData(&derIssuer);
        throw e;
    }
    CKYBuffer_FreeData(&certType);
    CKYBuffer_FreeData(&derSerial);
    CKYBuffer_FreeData(&derSubject);
    CKYBuffer_FreeData(&derIssuer);
}

Reader::Reader(unsigned long muscleObjID, CK_OBJECT_HANDLE handle, 
    const char *reader, const CKYBuffer *cardATR, bool isCoolkey) : 
        PKCS11Object(muscleObjID, handle)
{
    setAttributeULong(CKA_CLASS, CKO_MOZ_READER);
    setAttribute(CKA_LABEL, reader);
    setAttributeBool(CKA_TOKEN, TRUE);
    setAttributeBool(CKA_PRIVATE, FALSE);
    setAttributeBool(CKA_MODIFIABLE, FALSE);
    setAttributeBool(CKA_MOZ_IS_COOL_KEY, isCoolkey ? TRUE : FALSE);
    setAttribute(CKA_MOZ_ATR, cardATR);
}


CACPrivKey::CACPrivKey(CKYByte instance, const PKCS11Object &cert) : 
        PKCS11Object( ((int)'k') << 24 | ((int)instance+'0') << 16,
                         instance | 0x400)
{
    CKYBuffer id;
    CKYBuffer empty;
    CK_BBOOL decrypt = FALSE;

    /* So we know what the key is supposed to be used for based on
     * the instance */
    if (instance == 2) {
        decrypt = TRUE;
    }

    CKYBuffer_InitEmpty(&empty);
    setAttributeULong(CKA_CLASS, CKO_PRIVATE_KEY);
    setAttributeBool(CKA_TOKEN, TRUE);
    setAttributeBool(CKA_PRIVATE, FALSE);
    setAttribute(CKA_LABEL, cert.getAttribute(CKA_LABEL));
    setAttributeBool(CKA_MODIFIABLE, FALSE);
    CKYBuffer_InitFromLen(&id, 1);
    CKYBuffer_SetChar(&id, 1, instance+1);
    setAttribute(CKA_ID, &id);
    CKYBuffer_FreeData(&id);
    setAttribute(CKA_START_DATE, &empty);
    setAttribute(CKA_END_DATE, &empty);
    setAttributeBool(CKA_DERIVE, FALSE);
    setAttributeBool(CKA_LOCAL, TRUE);
    setAttributeULong(CKA_KEY_TYPE, CKK_RSA);

    setAttributeBool(CKA_SIGN, !decrypt);
    setAttributeBool(CKA_SIGN_RECOVER, !decrypt);
    setAttributeBool(CKA_UNWRAP, FALSE);
    setAttributeBool(CKA_SENSITIVE, TRUE);
    setAttributeBool(CKA_EXTRACTABLE, FALSE);

    CKYBuffer param1; CKYBuffer_InitEmpty(&param1);
    CKYBuffer param2; CKYBuffer_InitEmpty(&param2);

    try {
        const CKYBuffer *key = cert.getPubKey();
        keyType = GetKeyTypeFromSPKI(key);
        setKeyType(keyType);

        switch (keyType) {
        case rsa:
            GetKeyFields(key, &param1, &param2);
            setAttribute(CKA_MODULUS, &param1);
            setAttribute(CKA_PUBLIC_EXPONENT, &param2);
	    setAttributeULong(CKA_KEY_TYPE, CKK_RSA);
	    setAttributeBool(CKA_DECRYPT, decrypt);
	    setAttributeBool(CKA_DERIVE, FALSE);
            break;
        case ecc:
            GetECKeyFields(key, &param1, &param2);
            setAttribute(CKA_EC_POINT, &param1);
            setAttribute(CKA_EC_PARAMS, &param2);
	    setAttributeULong(CKA_KEY_TYPE, CKK_EC);
	    setAttributeBool(CKA_DECRYPT, FALSE);
	    setAttributeBool(CKA_DERIVE, decrypt);
            break;
        default:
            break;
        }
     } catch (PKCS11Exception &e) {
        CKYBuffer_FreeData(&param1);
        CKYBuffer_FreeData(&param2);
        throw e;
     }
     CKYBuffer_FreeData(&param1);
     CKYBuffer_FreeData(&param2);
}

CACPubKey::CACPubKey(CKYByte instance, const PKCS11Object &cert) : 
        PKCS11Object( ((int)'k') << 24 | ((int)(instance+'5')) << 16,
                       instance | 0x500)
{
    CKYBuffer id;
    CKYBuffer empty;
    CK_BBOOL encrypt = FALSE;

    /* So we know what the key is supposed to be used for based on
     * the instance */
    if (instance == 2) {
        encrypt = TRUE;
    }

    CKYBuffer_InitEmpty(&empty);
    setAttributeULong(CKA_CLASS, CKO_PUBLIC_KEY);
    setAttributeBool(CKA_TOKEN, TRUE);
    setAttributeBool(CKA_PRIVATE, FALSE);
    setAttribute(CKA_LABEL, cert.getAttribute(CKA_LABEL));
    setAttributeBool(CKA_MODIFIABLE, FALSE);
    CKYBuffer_InitFromLen(&id, 1);
    CKYBuffer_SetChar(&id, 1, instance+1);
    setAttribute(CKA_ID, &id);
    CKYBuffer_FreeData(&id);
    setAttribute(CKA_START_DATE, &empty);
    setAttribute(CKA_END_DATE, &empty);
    setAttributeBool(CKA_DERIVE, FALSE);
    setAttributeBool(CKA_LOCAL, TRUE);

    setAttributeBool(CKA_ENCRYPT, encrypt);
    setAttributeBool(CKA_VERIFY, !encrypt);
    setAttributeBool(CKA_VERIFY_RECOVER, !encrypt);
    setAttributeBool(CKA_WRAP, FALSE);

    CKYBuffer param1; CKYBuffer_InitEmpty(&param1);
    CKYBuffer param2; CKYBuffer_InitEmpty(&param2);

    try {
        const CKYBuffer *key = cert.getPubKey();
        keyType = GetKeyTypeFromSPKI(key);
        setKeyType(keyType);

        switch (keyType) {
        case rsa:
            GetKeyFields(key, &param1, &param2);
            setAttribute(CKA_MODULUS, &param1);
            setAttribute(CKA_PUBLIC_EXPONENT, &param2);
	    setAttributeULong(CKA_KEY_TYPE, CKK_RSA);
            break;
        case ecc:
            GetECKeyFields(key, &param1, &param2);
            setAttribute(CKA_EC_POINT, &param1);
            setAttribute(CKA_EC_PARAMS, &param2);
	    setAttributeULong(CKA_KEY_TYPE, CKK_EC);
            break;
        default:
            break;
        }
     } catch (PKCS11Exception &e) {
        CKYBuffer_FreeData(&param1);
        CKYBuffer_FreeData(&param2);
        throw e;
     }
     CKYBuffer_FreeData(&param1);
     CKYBuffer_FreeData(&param2);
}

static const char *CAC_Label[] = {
        "CAC ID Certificate",
        "CAC Email Signature Certificate",
        "CAC Email Encryption Certificate",
};

static const unsigned char CN_DATA[] = { 0x55, 0x4, 0x3 };
const unsigned int CN_LENGTH = sizeof(CN_DATA);

static SECStatus
GetCN(const CKYByte *dn, CKYSize dn_length, CCItem *cn)
{
    const CKYByte *buf;
    CKYSize buf_length;

    /* unwrap the sequence */
    buf = dataStart(dn,dn_length,&buf_length, false);
    if (buf == NULL) return SECFailure;

    while (buf_length) {
        const CKYByte *name;
        CKYSize name_length;
        const CKYByte *oid;
        CKYSize oid_length;

        /* unwrap the set */
        name = dataStart(buf, buf_length, &name_length, false);
	if (name == NULL) return SECFailure;

        /* advance to next set */
        buf_length -= (name-buf) + name_length;
        buf = name + name_length; 

        /* unwrap the Sequence */
        name = dataStart(name, name_length, &name_length, false);
	if (name == NULL) return SECFailure;

        /* unwrap the oid */
        oid = dataStart(name, name_length, &oid_length, false);
	if (oid == NULL) return SECFailure;

        /* test the oid */
        if (oid_length != CN_LENGTH) {
            continue;
        }
        if (memcmp(oid, CN_DATA, CN_LENGTH) != 0) {
            continue;
        }

        /* advance to CN */
        name_length -= (oid-name) + oid_length;
        name = oid + oid_length;

        /* unwrap the CN */
        cn->data = dataStart(name, name_length, &cn->len, false);
	if (cn->data == NULL) return SECFailure;
        return SECSuccess;
    }
    return SECFailure;
}

static char *
GetUserName(const CKYBuffer *dn)
{
    SECStatus rv;
    CCItem cn;
    char *string;

    rv = GetCN(CKYBuffer_Data(dn), CKYBuffer_Size(dn) , &cn);

    if( rv != SECSuccess ) {
        return NULL;
    }
    string = new char [ cn.len + 1 ];
    if (string == NULL) {
        return NULL;
    }
    memcpy(string, cn.data, cn.len);
    string[cn.len] = 0;
    return string;
}

CACCert::CACCert(CKYByte instance, const CKYBuffer *derCert) : 
        PKCS11Object( ((int)'c') << 24 | ((int)instance+'0') << 16, 
                        instance | 0x600)
{
    CKYBuffer id;
    CKYBuffer empty;

    CKYBuffer_InitEmpty(&empty);
    setAttributeULong(CKA_CLASS, CKO_CERTIFICATE);
    setAttributeBool(CKA_TOKEN, TRUE);
    setAttributeBool(CKA_PRIVATE, FALSE);
    setAttributeBool(CKA_MODIFIABLE, FALSE);
    CKYBuffer_InitFromLen(&id, 1);
    CKYBuffer_SetChar(&id, 1, instance+1);
    setAttribute(CKA_ID, &id);
    CKYBuffer_FreeData(&id);
    setAttributeULong(CKA_CERTIFICATE_TYPE, CKC_X_509);
    setAttribute(CKA_LABEL, CAC_Label[instance]);

    CKYBuffer derSerial; CKYBuffer_InitEmpty(&derSerial);
    CKYBuffer derSubject; CKYBuffer_InitEmpty(&derSubject);
    CKYBuffer derIssuer; CKYBuffer_InitEmpty(&derIssuer);

    CKYBuffer_Resize(&pubKey,0);

    try {
        setAttribute(CKA_VALUE, derCert);
        // infer cert attributes

        GetCertFields(derCert, &derSerial, &derSubject, &derIssuer, &pubKey);

        setAttribute(CKA_SERIAL_NUMBER, &derSerial);
        setAttribute(CKA_SUBJECT, &derSubject);
        setAttribute(CKA_ISSUER, &derIssuer);
   } catch (PKCS11Exception &e) {
        CKYBuffer_FreeData(&derSerial);
        CKYBuffer_FreeData(&derSubject);
        CKYBuffer_FreeData(&derIssuer);
        throw e;
    }

    name = GetUserName(&derSubject); /* adopt */
    CKYBuffer_FreeData(&derSerial);
    CKYBuffer_FreeData(&derSubject);
    CKYBuffer_FreeData(&derIssuer);
}

static const CKYByte rev[] = {
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
    0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
    0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
    0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
    0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
    0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
    0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
    0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
    0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
    0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
    0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
    0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
    0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
    0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
    0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
    0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
    0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
};

unsigned long GetBits(const CKYByte *entry, CKYSize entrySize,
				unsigned int numBits, unsigned int numBytes)
{
   unsigned long bits = 0;
   unsigned long bitFlag = 0;
   unsigned int i;

   /* size of zero is valid for no bits */
   if (entrySize <= 1) {
	return 0;
   }
   entrySize--;
   entry++;

   /* if we are longer than and unsigned, just bail now */
   if (entrySize > sizeof (unsigned long)) {
	bitFlag = BROKEN_FLAG;
	entrySize = sizeof(unsigned long);
   }
   /* turn the flags into an int */
   for (i=0; i < entrySize; i++) {
	CKYByte c = rev[entry[i]];
	bits  = bits | (((unsigned long)c) << (i*8));
   }
   return bits | bitFlag;
}


/*
 * parse the path object.
 * Caller has already unwrapped the outer ASN1Sequence
 */
CKYStatus PK15ObjectPath::setObjectPath(const CKYByte *current, CKYSize size)
{
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    unsigned int i;
    CKYStatus status;


    if ((current == NULL) || (current[0] != ASN1_OCTET_STRING)) {
	return CKYINVALIDDATA;
    }
    /* entry */
    entry = dataStart(current, size, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDDATA; }
    tagSize = entry - current;
    current += entrySize + tagSize;
    if (size < (entrySize + tagSize)) { return CKYINVALIDDATA; }
    size -= (entrySize +tagSize);
    status = CKYBuffer_Replace(&path, 0, entry, entrySize);
    if (status != CKYSUCCESS) {
	return status;
    }

    /* index */
    if ((size != 0) && current[0] ==  ASN1_INTEGER) { 
	entry = dataStart(current, size, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDDATA; }
	tagSize = entry - current;
	current += entrySize + tagSize;
	if (size < (entrySize + tagSize)) { return CKYINVALIDDATA; }
	size -= (entrySize +tagSize);
	if (entrySize > 5) { return CKYINVALIDDATA; }
	for (index = 0, i=0; i < entrySize; i++) {
	    index = (index << 8) + (unsigned int) entry[i];
	}
    }

    /* length */
    if ((size != 0) && ((current[0]|ASN1_CONSTRUCTED) ==  ASN1_CHOICE_0)) { 
	entry = dataStart(current, size, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDDATA; }
	tagSize = entry - current;
	current += entrySize + tagSize;
	if (size < (entrySize + tagSize)) { return CKYINVALIDDATA; }
	size -= (entrySize +tagSize);
	if (entrySize > 5) { return CKYINVALIDDATA; }
	for (length = 0, i=0; i < entrySize; i++) {
	    length = (length << 8) + (unsigned int) entry[i];
	}
    }
    return CKYSUCCESS;
}

static unsigned int pK15GetTag(PK15ObjectType type) {
     switch (type) { case PK15PvKey: case PK15PuKey: return 'k'<<24;
		     case PK15Cert: return 'c' << 24; default: break; }
     return 'v';
}


PK15Object::PK15Object(CKYByte inst, PK15ObjectType type, 
	const CKYByte *der, CKYSize derSize) 
	: PKCS11Object(pK15GetTag(type) | ((inst+'0') << 16), 0xa000 | inst)
{
    CKYStatus status;

    instance = inst;
    p15Type =  type;
    CKYBuffer_InitEmpty(&authId);
    CKYBuffer_InitEmpty(&pinAuthId);
    state = PK15StateInit;
    pinInfo.pinFlags = 0;
    pinInfo.pinType = P15PinUTF8;
    pinInfo.minLength = 4;
    pinInfo.storedLength = 0;
    pinInfo.maxLength = 0;
    pinInfo.pinRef = 0;
    pinInfo.padChar = 0xff;

    status = completeObject(der, derSize);
    if (status != CKYSUCCESS) {
	state = PK15StateInit; /* don't try to fetch any more if we failed */
    }
}

/* returns true if there is more work to do... */
CKYStatus 
PK15Object::completeObject(const CKYByte *current, CKYSize currentSize)
{
    const CKYByte *commonAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYByte objectTag;
    CKYStatus status;
    CKYBitFlags bits;

    switch (state) {
    case PK15StateInit:
    case PK15StateNeedObject:
	break;
    case PK15StateNeedRawPublicKey:
	return  completeRawPublicKey(current, currentSize);
    case PK15StateNeedRawCertificate:
	return  completeRawCertificate(current, currentSize);
    case PK15StateComplete:
	return CKYSUCCESS;
    }

    if (current == NULL) { return CKYINVALIDARGS; }

    objectTag = current[0];

    setAttributeBool(CKA_TOKEN, TRUE);

    /* set type specific attributes */
    switch (p15Type) {
    case PK15Cert:
	setAttributeULong(CKA_CLASS, CKO_CERTIFICATE);
    	setAttributeULong(CKA_CERTIFICATE_TYPE, CKC_X_509);
	if (objectTag != PK15X509CertType) {
	    return CKYUNSUPPORTED;
	}
	break;
    case PK15PvKey:
	setAttributeULong(CKA_CLASS, CKO_PRIVATE_KEY);
	goto set_key_type;
    case PK15PuKey:
	setAttributeULong(CKA_CLASS, CKO_PUBLIC_KEY);
set_key_type:
	switch (objectTag) {
	case PK15RSAKeyType:
	    keyType = rsa;
	    setAttributeULong(CKA_KEY_TYPE, CKK_RSA);
	    break;
	case PK15ECCKeyType:
	    keyType = ecc;
	    setAttributeULong(CKA_KEY_TYPE, CKK_EC);
	    break;
	case PK15DSAKeyType:
	case PK15DHKeyType:
	default:
	    return CKYUNSUPPORTED;
	}
	break;
    case PK15AuthObj:
	setAttributeULong(CKA_CLASS, CKO_DATA);
	break;
    default:
	return CKYUNSUPPORTED;
    }

    /* unwrap the object */	
    current = dataStart(current, currentSize, &currentSize, false);
    if (current == NULL) { return CKYINVALIDDATA; }

    /*
     * parse the Common Attributes 
     *     label UTF8_STRING
     *     flags BIT_STRING (optional)
     *     authid OCTET_STRING (optional)
     */
    if ((current == NULL) || (current[0] != ASN1_SEQUENCE)) 
	{ return CKYINVALIDDATA; }
    /* unwrap */
    commonAttributes = dataStart(current, currentSize, &commonSize, false);
    if (commonAttributes == NULL) { return CKYINVALIDDATA; }

    /* point current to the next section (cass attributes)  */
    tagSize = commonAttributes - current;
    current += commonSize + tagSize;
    if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
    currentSize -= (commonSize +tagSize);

    /* get the CKA_LABEL */
    if (commonAttributes[0] != ASN1_UTF8_STRING) { return CKYINVALIDDATA; }
    entry = dataStart(commonAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonAttributes;
    commonAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    setAttribute(CKA_LABEL, entry, entrySize);

    /* parse optional flags */
    bits = BROKEN_FLAG;
    if (commonAttributes[0] == ASN1_BIT_STRING) {
	entry = dataStart(commonAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAttributes;
	commonAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	bits = GetBits(entry,entrySize,2,1);
    }

    if (commonAttributes[0] == ASN1_OCTET_STRING) {
	entry = dataStart(commonAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAttributes;
	commonAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	status = CKYBuffer_Replace(&authId, 0, entry, entrySize);
	if (status != CKYSUCCESS) {
	   return status;
	}
    }

    if (bits & BROKEN_FLAG) {
	bits = defaultCommonBits();
    }
    setAttributeBool(CKA_PRIVATE, 
		(bits & P15FlagsPrivate) ? TRUE: FALSE);
    setAttributeBool(CKA_MODIFIABLE, FALSE); /* our token is ReadOnly, so the
					      * object is never modifiable for
					      * us */
    /* future common attributes here */

    /*
     *  Parse Class variables
     *
     */
    switch (p15Type) {
    case PK15Cert:
	status = completeCertObject(current,currentSize);
	break;
    case PK15PuKey:
    case PK15PvKey:
	status = completeKeyObject(current,currentSize);
	break;
    case PK15AuthObj:
	status = completeAuthObject(current, currentSize);
	break;
    }
    return status;
}


CKYStatus 
PK15Object::completeCertObject(const CKYByte *current, CKYSize currentSize)
{
    const CKYByte *commonCertAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYBuffer empty;
    CKYStatus status;
    CKYByte valueTag;

    CKYBuffer_InitEmpty(&empty);

    /*
     * parse the Common Cert Attributes 
     *     id OCTET_STRING
     *     authority BOOLEAN DEFAULT FALSE
     *     requestId BIT_STRING (optional)
     *     thumbprint [0] PKS15OOBCertHash (optional)
     */
    if ((current == NULL) || (current[0] != ASN1_SEQUENCE)) 
		{ return CKYINVALIDARGS; }
    /* unwrap */
    commonCertAttributes = dataStart(current, currentSize, &commonSize, false);
    if (commonCertAttributes == NULL) { return CKYINVALIDDATA; }
    /* point current to the next section (type attributes)  */
    tagSize = commonCertAttributes - current;
    current += commonSize + tagSize;
    if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
    currentSize -= (commonSize +tagSize);

    /* get the id */
    if (commonCertAttributes[0] != ASN1_OCTET_STRING) { return CKYINVALIDDATA; }
    entry = dataStart(commonCertAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonCertAttributes;
    commonCertAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    setAttribute(CKA_ID, entry, entrySize);


    /* skip authority (currently unused) */
    /* skip requestID */
    /* skip thumbprint */
    /* future common cert attributes here */

    /* certs have not subclass attributes  ASN1_CHOICE_0 */

    /* handle the X509 type attributes */
    if (current[0] != ASN1_CHOICE_1) { return CKYINVALIDDATA; }
    /* unwrap */
    commonCertAttributes = dataStart(current, currentSize, &commonSize, false);
    if (commonCertAttributes == NULL) { return CKYINVALIDDATA; }
   
    /*
     * PCKS11X504CertificateAttributes
     *     value   SEQUENCE or CHOICE_0
     *     ... don't care about the rest.
     */
    valueTag = commonCertAttributes[0];
    /* unwrapp */
    entry = dataStart(commonCertAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDDATA; }
    if (valueTag == ASN1_SEQUENCE) {
    	entry = dataStart(entry, entrySize, &entrySize, false);
    	if (entry == NULL) { return CKYINVALIDDATA; }
	/* if we have a path, the actual object is in another file,
	 * tell the caller to get it and come back here */
	status = objectPath.setObjectPath(entry, entrySize);
	state = PK15StateNeedRawCertificate;
        return status;
    }
    if (valueTag != ASN1_CHOICE_0) {
	return CKYINVALIDDATA;
    }
    return  completeRawCertificate(entry, entrySize);
}

CKYStatus 
PK15Object::completeAuthObject(const CKYByte *current, CKYSize currentSize)
{
    const CKYByte *commonAuthAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYBuffer empty;
    CKYStatus status;

    CKYBuffer_InitEmpty(&empty);

    if (current == NULL) { return CKYINVALIDARGS; }
    /* common Auth attributes */
    if (current[0] == ASN1_SEQUENCE) {
         /* unwrap */
        commonAuthAttributes = 
			dataStart(current, currentSize, &commonSize, false);
	if (commonAuthAttributes == NULL) { return CKYINVALIDDATA; }
	tagSize = commonAuthAttributes - current;
	current += commonSize + tagSize;
	if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
	currentSize -= (commonSize + tagSize);
	if (commonAuthAttributes[0] != ASN1_OCTET_STRING) {
	    return CKYINVALIDDATA;
	}
	entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	status = CKYBuffer_Replace(&pinAuthId, 0, entry, entrySize);
	if (status != CKYSUCCESS) {
	   return status;
	}
	
    }
    /* auth specific values */
    if (current[0] != ASN1_CHOICE_1) { return CKYINVALIDARGS; }
    /* unwrap */
    commonAuthAttributes = dataStart(current, currentSize, &commonSize, false);
    if (commonAuthAttributes == NULL) { return CKYINVALIDDATA; }
    tagSize = commonAuthAttributes - current;
    current += commonSize + tagSize;
    if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
    currentSize -= (commonSize + tagSize);
    /*
     * parse the Pin Auth Attributes 
     *     pinFlags  BIT_STRING
     *     pinType   ENUMERATED (bcd, ascii-numeric, utf8)
     *     minLength INTEGER
     *     storedLength INTEGER
     *     maxlength INTEGER (optional)
     *     pinReference CHOICE_0 (optional)
     *     padChar OCTET_STRING (optional)
     *     lastPinChange GENERALIZED_TIME (optional)
     *     path PKCS15Path (optional)
     */
    if (commonAuthAttributes[0] != ASN1_SEQUENCE) { return CKYINVALIDARGS; }
    commonAuthAttributes = dataStart(commonAuthAttributes, 
					commonSize, &commonSize, false);
    if (commonAuthAttributes == NULL) { return CKYINVALIDDATA; }

    /* parse pin flags */
    if (commonAuthAttributes[0] != ASN1_BIT_STRING) { return CKYINVALIDDATA; }

    entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonAuthAttributes;
    commonAuthAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    pinInfo.pinFlags = GetBits(entry,entrySize,9,2);


    /* parse PinType */
    if (commonAuthAttributes[0] != ASN1_ENUMERATED) { return CKYINVALIDDATA; }
    entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonAuthAttributes;
    commonAuthAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    /* turn entry into an int */
    if (entrySize > 1) { return CKYINVALIDARGS; }
    pinInfo.pinType = (P15PinType) *entry;

    /* parse minLength */
    if (commonAuthAttributes[0] != ASN1_INTEGER) { return CKYINVALIDDATA; }
    entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonAuthAttributes;
    commonAuthAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    if (entrySize > 1) { return CKYINVALIDARGS; }
    pinInfo.minLength = *entry;

    /* parse storedLength */
    if (commonAuthAttributes[0] != ASN1_INTEGER) { return CKYINVALIDDATA; }
    entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonAuthAttributes;
    commonAuthAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    if (entrySize > 1) { return CKYINVALIDARGS; }
    pinInfo.storedLength = *entry;

    /* parse maxLength (optional) */
    if (commonAuthAttributes[0] == ASN1_INTEGER) { 
	unsigned long maxPin;
	entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize > sizeof (maxPin)) { return CKYINVALIDARGS; }
	maxPin = 0; 
	CKYSize i;
	for (i=0; i < entrySize; i++) {
	    maxPin = (maxPin << 8) | entry[i];
	}
	pinInfo.maxLength = maxPin;
    }

    /* parse pin ref  (optional) */
    if ((commonAuthAttributes[0]|ASN1_CONSTRUCTED) == ASN1_CHOICE_0)  {
	CKYByte pinRef;
	entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize > 2) { return CKYINVALIDARGS; }
	if (entrySize == 2) {
	    if (*entry != 0) { return CKYINVALIDARGS; }
	    pinRef = entry[1];
	} else pinRef = entry[0];
	pinInfo.pinRef = pinRef;
    }

    /* parse padChar */
    if (commonAuthAttributes[0] == ASN1_OCTET_STRING) { 
	entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize > 1) { return CKYINVALIDARGS; }
	pinInfo.padChar = *entry;
    }

    /* skip lastPinChange */
    if (commonAuthAttributes[0] == ASN1_GENERALIZED_TIME) { 
	entry = dataStart(commonAuthAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
    }
    /* parse path */
    if (commonAuthAttributes[0] == ASN1_SEQUENCE) { 
	entry = dataStart(commonAuthAttributes, commonSize, 
							&entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonAuthAttributes;
	commonAuthAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	/* if we have a path, the actual object is in another file,
	 * tell the caller to get it and come back here */
	status = objectPath.setObjectPath(entry, entrySize);
	if (status != CKYSUCCESS) { return status; }
    }
    state = PK15StateComplete;
    return CKYSUCCESS;
}

CKYStatus
PK15Object::completeKeyObject(const CKYByte *current, CKYSize currentSize)
{
    const CKYByte *commonKeyAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYBuffer empty;
    CKYStatus status;
    unsigned long bits;
    /*bool native; */

    CKYBuffer_InitEmpty(&empty);
    /*
     * parse the Common Key Attributes 
     *     id OCTET_STRING
     *     usageFlags BIT_STRING 
     *     native BOOLEAN DEFAULT TRUE
     *     accessFlags BIT_STRING (optional)
     *     keyReference OCTET_STRING (optional)
     *     startDate GENERALIZED_TIME (optional)
     *     endDate [0] GENERALIZED_TYPE (optional)
     */
    if ((current == NULL) || (current[0] != ASN1_SEQUENCE)) 
		{ return CKYINVALIDARGS; }
    /* unwrap */
    commonKeyAttributes = dataStart(current, currentSize, &commonSize, false);
    if (commonKeyAttributes == NULL) { return CKYINVALIDDATA; }

    /* point current to the next section (sublcass attributes)  */
    tagSize = commonKeyAttributes - current;
    current += commonSize + tagSize;
    if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
    currentSize -= (commonSize + tagSize);

    /* get the id */
    if (commonKeyAttributes[0] != ASN1_OCTET_STRING) { return CKYINVALIDDATA; }
    entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonKeyAttributes;
    commonKeyAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    setAttribute(CKA_ID, entry, entrySize);

    /* parse flags */
    if (commonKeyAttributes[0] != ASN1_BIT_STRING) { return CKYINVALIDDATA; }
    entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonKeyAttributes;
    commonKeyAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    bits = GetBits(entry,entrySize,10,2);
    if (bits & BROKEN_FLAG) {
	bits = defaultUsageBits();
    }
    setAttributeBool(CKA_ENCRYPT,
			(bits & P15UsageEncrypt)          ? TRUE : FALSE);
    setAttributeBool(CKA_DECRYPT,
			(bits & P15UsageDecrypt)          ? TRUE : FALSE);
    setAttributeBool(CKA_SIGN,
			(bits & P15UsageSign)             ? TRUE : FALSE);
    setAttributeBool(CKA_SIGN_RECOVER,
			(bits & P15UsageSignRecover)      ? TRUE : FALSE);
    setAttributeBool(CKA_WRAP,
			(bits & P15UsageWrap)             ? TRUE : FALSE);
    setAttributeBool(CKA_UNWRAP,
			(bits & P15UsageUnwrap)           ? TRUE : FALSE);
    setAttributeBool(CKA_VERIFY,
			(bits & P15UsageVerify)           ? TRUE : FALSE);
    setAttributeBool(CKA_VERIFY_RECOVER,
			(bits & P15UsageVerifyRecover)    ? TRUE : FALSE);
    setAttributeBool(CKA_DERIVE,
			(bits & P15UsageDerive)           ? TRUE : FALSE);
    /* no CKA value for P15UsageNonRepudiation */
    if (bits & P15UsageNonRepudiation) {
	/* set signing and sign recover. Non-repudiation keys are automatically
         * signing keys */
	setAttributeBool(CKA_SIGN, TRUE);
	if (keyType == rsa) {
	    setAttributeBool(CKA_SIGN_RECOVER, TRUE);
	}
    }

    /* parse native (currently unused) */
    /*native=true; */
    if (commonKeyAttributes[0] == ASN1_BOOLEAN) {
	entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonKeyAttributes;
	commonKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	/*if ((entrySize == 1) && (entry[0] == 0)) {
	    native = false;
	} */
    }
    /* parse access flags */
    bits = BROKEN_FLAG;
    if (commonKeyAttributes[0] == ASN1_BIT_STRING) {
	entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonKeyAttributes;
	commonKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	bits = GetBits(entry,entrySize,4,1);
    }
    if (bits & BROKEN_FLAG) {
	bits = defaultAccessBits();
    }
    setAttributeBool(CKA_SENSITIVE,  
			(bits & P15AccessSensitive)       ? TRUE : FALSE);
    setAttributeBool(CKA_EXTRACTABLE,
			(bits & P15AccessExtractable)     ? TRUE : FALSE);
    setAttributeBool(CKA_ALWAYS_SENSITIVE, 
			(bits & P15AccessAlwaysSenstive)  ? TRUE : FALSE);
    setAttributeBool(CKA_NEVER_EXTRACTABLE,
			(bits & P15AccessNeverExtractable)? TRUE : FALSE);
    setAttributeBool(CKA_LOCAL,      
			(bits & P15AccessLocal)           ? TRUE : FALSE);

    /* parse the key reference */
    keyRef = PK15_INVALID_KEY_REF; /* invalid keyRef */
    if (commonKeyAttributes[0] == ASN1_INTEGER) {
	entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonKeyAttributes;
	commonKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize == 1) {
	    keyRef = entry[0];
	} else if ((entrySize == 2) && (entry[0] == 0)) {
	    keyRef = entry[1];
	}
    }
    setAttribute(CKA_START_DATE, &empty);
    if (commonKeyAttributes[0] == ASN1_GENERALIZED_TIME) {
	entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonKeyAttributes;
	commonKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	setAttribute(CKA_START_DATE,entry, entrySize);
    }
    setAttribute(CKA_END_DATE, &empty);
    if (commonKeyAttributes[0] == ASN1_CHOICE_0) {
	entry = dataStart(commonKeyAttributes, commonSize, &entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonKeyAttributes;
	commonKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	setAttribute(CKA_END_DATE,entry, entrySize);
    }
    /* future common key attributes here */

    /*
     *  Parse Class variables
     *
     */
    switch (p15Type) {
    case PK15PuKey:
	status = completePubKeyObject(current,currentSize);
	break;
    case PK15PvKey:
	status = completePrivKeyObject(current,currentSize);
	break;
    default:
	status=CKYLIBFAIL; /* shouldn't happen */
	break;
    }
    return status;
}

CKYStatus PK15Object::completePrivKeyObject(const CKYByte *current,
							CKYSize currentSize)
{
    const CKYByte *commonPrivKeyAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYBuffer empty;
    CKYStatus status;
    unsigned int modulusSize;
    unsigned int i;

    CKYBuffer_InitEmpty(&empty);
    if (current == NULL) { return CKYINVALIDARGS; }

    /* optional subclass = CommonPrivateKeyAttributes */
    if (current[0] == ASN1_CHOICE_0) {
	/*
         * PKCS15CommonPrivateKeyAttributes
         *
         * subjectName   SEQUENCE optional
         * keyIdentifiers CHOICE 0  optional
         */
	/* unwrap */
	commonPrivKeyAttributes = 
			dataStart(current, currentSize, &commonSize, false);
	if (commonPrivKeyAttributes == NULL) { return CKYINVALIDDATA; }
	/* point current to the next section (type attributes)  */
	tagSize = commonPrivKeyAttributes - current;
	current += commonSize + tagSize;
	if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
	currentSize -= (commonSize +tagSize);

 	/* subjectName */
	if (commonPrivKeyAttributes[0] == ASN1_SEQUENCE) {
	    entry = dataStart(commonPrivKeyAttributes, commonSize, 
							&entrySize, false);
	    if (entry == NULL) { return CKYINVALIDARGS; }
	    tagSize = entry - commonPrivKeyAttributes;
	    commonPrivKeyAttributes += entrySize + tagSize;
	    commonSize -= (entrySize +tagSize);
	    setAttribute(CKA_SUBJECT, entry, entrySize);
	}

	/* keyIdentfiers */
	/* future CommonPrivateKeyAttributes here */
    }

    
    /* Type attributes (either PKCS15RSAPrivateKeyAttributes or 
     * PKCS15ECCPrivateKeyAttributes) -- Not Optional */
    if (current[0] != ASN1_CHOICE_1) { return CKYINVALIDDATA; }
    /*
     *    PKCS15RSAPrivateKeyAttributes
     *        value PKCS15ObjectValue
     *        modulusLength INTEGER
     *        keyInfo SEQUENCE optional
     *    PKCS15ECCPrivateKeyAttributes
     *        value PKCS15ObjectValue
     *        keyInfo SEQUENCE optional
     */
    /* unwrap */
    commonPrivKeyAttributes = 
			dataStart(current, currentSize, &commonSize, false);
    if (commonPrivKeyAttributes == NULL) { return CKYINVALIDDATA; }

    /* value */
     /* don't support direct private key objects */
    if (commonPrivKeyAttributes[0] == ASN1_CHOICE_0) { return CKYUNSUPPORTED;  }
    if (commonPrivKeyAttributes[0] != ASN1_SEQUENCE) { return CKYINVALIDDATA; }
    commonPrivKeyAttributes = dataStart(commonPrivKeyAttributes, commonSize, &commonSize, false);
    if (commonPrivKeyAttributes == NULL) { return CKYINVALIDARGS; }
    entry = dataStart(commonPrivKeyAttributes, commonSize, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDARGS; }
    tagSize = entry - commonPrivKeyAttributes;
    commonPrivKeyAttributes += entrySize + tagSize;
    commonSize -= (entrySize +tagSize);
    /* if we have a path, the actual object is in another file,
     * tell the caller to get it and come back here */
    status = objectPath.setObjectPath(entry, entrySize);
    if (status != CKYSUCCESS) { return status; }

    /* parse modulus size */
    if ((keyType == rsa) && commonPrivKeyAttributes[0] == ASN1_INTEGER) {
	entry = dataStart(commonPrivKeyAttributes, commonSize, 
							&entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonPrivKeyAttributes;
	commonPrivKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize > 4) {
	   return CKYINVALIDDATA;
	}
	for (modulusSize = 0, i=0; i < entrySize; i++) {
	   modulusSize = (modulusSize << 8) + entry[i];
	}
	setKeySize(modulusSize);
    }

    if (keyType == rsa) {
	state = PK15StateComplete;
	return CKYSUCCESS; /* we're done with RSA */
    }

    /* parse keyinfo  at this point all we are after is the EC_PARAM*/
    if (commonPrivKeyAttributes[0] == ASN1_SEQUENCE) {
	/* unwrap */
	commonPrivKeyAttributes = dataStart(commonPrivKeyAttributes, 
					commonSize, &commonSize, true);
	if (commonPrivKeyAttributes == NULL) { return CKYINVALIDDATA; }
	if (commonPrivKeyAttributes[0] == ASN1_SEQUENCE) {
	    entry = dataStart(commonPrivKeyAttributes, commonSize, 
							&entrySize, true);
	    if (entry == NULL) { return CKYINVALIDDATA; }
	    setAttribute(CKA_EC_PARAMS, entry, entrySize);
	}
    }
    state = PK15StateComplete;
    return CKYSUCCESS;
}

CKYStatus 
PK15Object::completePubKeyObject(const CKYByte *current, CKYSize currentSize)
{
    const CKYByte *commonPubKeyAttributes;
    CKYSize commonSize;
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;
    CKYBuffer empty;
    CKYStatus status;
    unsigned int modulusSize;
    unsigned int i;

    CKYBuffer_InitEmpty(&empty);
    if (current == NULL) { return CKYINVALIDDATA; }

    /* optional subclass = CommonPublicKeyAttributes */
    if (current[0] == ASN1_CHOICE_0) {
	/*
         * PKCS15CommonPublicKeyAttributes
         *
         * subjectName   SEQUENCE optional
         * keyIdentifiers CHOICE 0  optional
         */
	/* unwrap */
	commonPubKeyAttributes = 
			dataStart(current, currentSize, &commonSize, false);
	if (commonPubKeyAttributes == NULL) { return CKYINVALIDDATA; }
	/* point current to the next section (type attributes)  */
	tagSize = commonPubKeyAttributes - current;
	current += commonSize + tagSize;
	if (currentSize < (commonSize + tagSize)) { return CKYINVALIDDATA; }
	currentSize -= (commonSize + tagSize);

 	/* subjectName */
	if (commonPubKeyAttributes[0] == ASN1_SEQUENCE) {
	    entry = dataStart(commonPubKeyAttributes, commonSize, 
							&entrySize, false);
	    if (entry == NULL) { return CKYINVALIDARGS; }
	    tagSize = entry - commonPubKeyAttributes;
	    commonPubKeyAttributes += entrySize + tagSize;
	    commonSize -= (entrySize +tagSize);
	    setAttribute(CKA_SUBJECT, entry, entrySize);
	}
	/* future CommonPublicKeyAttributes here */
    }

    
    /* Type attributes (either PKCS15RSAPublicKeyAttributes or 
     * PKCS15ECCPublicKeyAttributes) -- Not Optional */
    if (current[0] != ASN1_CHOICE_1) { return CKYINVALIDDATA; }
    /*
     *    PKCS15RSAPublicKeyAttributes
     *        value PKCS15ObjectValue
     *        modulusLength INTEGER
     *        keyInfo SEQUENCE optional
     *    PKCS15ECCPublicKeyAttributes
     *        value PKCS15ObjectValue
     *        keyInfo SEQUENCE optional
     */
    /* unwrap */
    commonPubKeyAttributes = 
			dataStart(current, currentSize, &commonSize, false);
    if (commonPubKeyAttributes == NULL) { return CKYINVALIDDATA; }

    /* value */
    if (commonPubKeyAttributes[0] == ASN1_CHOICE_0) { 
    	entry = dataStart(commonPubKeyAttributes, commonSize, 
							&entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	status = completeRawPublicKey(entry, entrySize);
	if (status != CKYSUCCESS) { return status; }
    } else if (commonPubKeyAttributes[0] == ASN1_SEQUENCE) { 
	entry = dataStart(commonPubKeyAttributes, commonSize, 
							&entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonPubKeyAttributes;
	commonPubKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	/* if we have a path, the actual object is in another file,
	 * tell the caller to get it and come back here */
	status = objectPath.setObjectPath(entry, entrySize);
	if (status != CKYSUCCESS) { return status; }
	state = PK15StateNeedRawPublicKey;
    }

    /* parse modulus size */
    if ((keyType == rsa) && commonPubKeyAttributes[0] == ASN1_INTEGER) {
	entry = dataStart(commonPubKeyAttributes, commonSize, 
							&entrySize, false);
	if (entry == NULL) { return CKYINVALIDARGS; }
	tagSize = entry - commonPubKeyAttributes;
	commonPubKeyAttributes += entrySize + tagSize;
	commonSize -= (entrySize +tagSize);
	if (entrySize > 4) {
	   return CKYINVALIDDATA;
	}
	for (modulusSize = 0, i=0; i < entrySize; i++) {
	   modulusSize = (modulusSize << 8) + entry[i];
	}
	setKeySize(modulusSize);
    }

    if (keyType == rsa) {
	return CKYSUCCESS; /* we're done with RSA */
    }

    /* parse keyinfo  at this point all we are after is the EC_PARAM*/
    if (commonPubKeyAttributes[0] == ASN1_SEQUENCE) {
	/* unwrap */
	commonPubKeyAttributes = dataStart(commonPubKeyAttributes, 
					commonSize, &commonSize, true);
	if (commonPubKeyAttributes == NULL) { return CKYINVALIDDATA; }
	if (commonPubKeyAttributes[0] == ASN1_SEQUENCE) {
	    entry = dataStart(commonPubKeyAttributes, commonSize, 
							&entrySize, true);
	    if (entry == NULL) { return CKYINVALIDDATA; } 
	    setAttribute(CKA_EC_PARAMS, entry, entrySize);
	}
    }
    return CKYSUCCESS;

}

CKYStatus 
PK15Object::completeRawCertificate(const CKYByte *derCert, CKYSize derCertSize)
{
    SECStatus rv;
    CCItem issuerItem, serialItem, derSerialItem, subjectItem,
        validityItem, subjectKeyItem;
    const char *certLabel;

    setAttribute(CKA_VALUE, derCert, derCertSize);
    rv = GetCertFieldItems(derCert, derCertSize, 
        &issuerItem, &serialItem, &derSerialItem, &subjectItem, &validityItem,
        &subjectKeyItem);
    if (rv != SECSuccess) {
	return CKYINVALIDDATA;
    }
    setAttribute(CKA_SERIAL_NUMBER, derSerialItem.data, derSerialItem.len);
    setAttribute(CKA_SUBJECT, subjectItem.data, subjectItem.len);
    setAttribute(CKA_ISSUER, issuerItem.data, issuerItem.len);
    CKYBuffer_Replace(&pubKey, 0, subjectKeyItem.data, subjectKeyItem.len);
    /* if we didn't get a label, set one based on the CN */
    certLabel = getLabel();
    if ((certLabel == NULL) || (*certLabel == 0)) {
	CKYBuffer subject;
	char *newLabel;
	CKYBuffer_InitFromData(&subject, subjectItem.data, subjectItem.len);
	newLabel = GetUserName(&subject);
	if (newLabel) {
	    setAttribute(CKA_LABEL, (CKYByte *)newLabel, 
					(CKYSize) strlen(newLabel)-1);
	    delete [] newLabel;
	}
	CKYBuffer_FreeData(&subject);
    }
    state = PK15StateComplete;
    return CKYSUCCESS;
}

CKYStatus 
PK15Object::completeRawPublicKey(const CKYByte *current, CKYSize size)
{
    const CKYByte *entry;
    CKYSize entrySize;
    CKYSize tagSize;

    if ((current == NULL) || (current[0] != ASN1_SEQUENCE)) {
	return CKYINVALIDDATA;
    }
    /* unwrap*/
    current = dataStart(current, size, &size, false);
    if (current == NULL) { return CKYINVALIDDATA; }

    /* modulus */
    if (current[0] != ASN1_INTEGER) { return CKYINVALIDDATA; }
    entry = dataStart(current, size, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDDATA; }
    tagSize = entry - current;
    current += entrySize + tagSize;
    if (size < (entrySize + tagSize)) { return CKYINVALIDDATA; }
    size -= (entrySize +tagSize);
    if ((entry[0] == 0) && (entrySize > 1)) {
	entry++; entrySize--;
    }
    setAttribute(CKA_MODULUS, entry, entrySize);

    /* exponent */
    if (current[0] != ASN1_INTEGER) { return CKYINVALIDDATA; }
    entry = dataStart(current, size, &entrySize, false);
    if (entry == NULL) { return CKYINVALIDDATA; }
    tagSize = entry - current;
    current += entrySize + tagSize;
    if (size < (entrySize + tagSize)) { return CKYINVALIDDATA; }
    size -= (entrySize + tagSize);
    if ((entry[0] == 0) && (entrySize > 1)) {
	entry++; entrySize--;
    }
    setAttribute(CKA_PUBLIC_EXPONENT, entry, entrySize);
    state = PK15StateComplete;
    return CKYSUCCESS;
}

DEREncodedSignature::DEREncodedSignature(const CKYBuffer *derSig)
{

    CKYBuffer_InitEmpty(&derEncodedSignature);
    CKYBuffer_InitFromCopy(&derEncodedSignature, derSig);


}

DEREncodedSignature::~DEREncodedSignature()
{

    CKYBuffer_FreeData(&derEncodedSignature);

}

int DEREncodedSignature::getRawSignature(CKYBuffer *rawSig,
					 unsigned int keySize)
{

    const CKYByte *buf = NULL;

    if (rawSig == NULL) {
        return -1;
    }

    if (CKYBuffer_Size(&derEncodedSignature) == 0) {
        return -1;
    }

    CKYBuffer_Zero(rawSig);

    CKYSize seq_length = 0;
    CKYSize expected_sig_len = ( (keySize + 7) / 8 ) * 2 ;
    CKYSize expected_piece_size = expected_sig_len / 2 ;

    /* unwrap the sequence */
    buf = dataStart(CKYBuffer_Data(&derEncodedSignature), CKYBuffer_Size(&derEncodedSignature),&seq_length, false);

    if (buf == NULL) return -1;

    // unwrap first multi byte integer
   
    CKYSize int_length = 0;
    const CKYByte *int1Buf = NULL;
    const CKYByte *int2Buf = NULL;

    int1Buf = dataStart(buf, seq_length, &int_length, false );

    if (int1Buf == NULL) return -1;
    //advance to next entry

    if (int_length > expected_piece_size) {

      unsigned int diff = int_length - expected_piece_size ;

      /* Make sure we are chopping off zeroes 
         Otherwise give up. */

      for (int i = 0 ; i < (int) diff ; i++) {
          if ( int1Buf[i] != 0) 
              return -1;
      }

      int_length -= diff;
      int1Buf += diff;

    }

    seq_length -= (int1Buf -buf) + int_length;
    buf = int1Buf +  int_length;

    // unwrap second multi byte integer

    CKYSize second_int_length = 0;

    int2Buf = dataStart(buf, seq_length, &second_int_length, false);

    if (int2Buf == NULL) return -1;


    if (second_int_length > expected_piece_size) {
        unsigned int diff = second_int_length - expected_piece_size ;

        /* Make sure we are chopping off zeroes 
           Otherwise give up. */

        for (int i = 0 ;  i < (int)  diff ; i++) {
            if ( int2Buf[i] != 0) 
                return -1;
        }
      
        second_int_length -= diff;
        int2Buf += diff;
    }

    CKYBuffer_AppendData(rawSig, int1Buf, int_length);
    CKYBuffer_AppendData(rawSig, int2Buf, second_int_length);

    return CKYSUCCESS;
}


DEREncodedTokenInfo::DEREncodedTokenInfo(CKYBuffer *derTokenInfo)
{
    const CKYByte *current = CKYBuffer_Data(derTokenInfo);
    const CKYByte *entry;
    CKYSize size = CKYBuffer_Size(derTokenInfo);
    CKYSize entrySize;
    CKYSize tagSize;
    /* set token name, etc */

    version = -1;
    CKYBuffer_InitEmpty(&serialNumber);
    manufacturer = NULL;
    tokenName = NULL;

    if (current[0] != ASN1_SEQUENCE) {
	return; /* just use the defaults */
    }
    /* unwrap */
    current = dataStart(current, size, &size, false);
    if (current == NULL) return;

    /* parse the version */
    if (current[0] != ASN1_INTEGER) { return; }
    entry = dataStart(current, size, &entrySize, false);
    if (entry == NULL) return;
    tagSize = entry - current;
    current += tagSize + entrySize;
    if (size < tagSize + entrySize) return;
    size -= tagSize + entrySize;
    if (entrySize < 1) {
	version = *entry;
    }

    /* get the serial number */
    if (current[0] != ASN1_OCTET_STRING) { return ; }
    entry = dataStart(current, size, &entrySize, false);
    if (entry == NULL) return;
    tagSize = entry - current;
    current += tagSize + entrySize;
    size -= tagSize + entrySize;
    CKYBuffer_Replace(&serialNumber, 0, entry, entrySize);
    /* should we fake the cuid here? */

    /* get the optional manufacture ID */
    if (current[0] == ASN1_UTF8_STRING) {
	entry = dataStart(current, size, &entrySize, false);
	if (entry == NULL) return;
	tagSize = entry - current;
	current += tagSize + entrySize;
	size -= tagSize + entrySize;
	manufacturer = (char *)malloc(entrySize+1);
	if (manufacturer) {
	    memcpy(manufacturer, entry, entrySize);
	    manufacturer[entrySize] = 0;
	}
    }

    /* get the optional token name */
    /* most choices are constructed, 
     * but this one isn't explicity add the flag */
    if ((current[0]|ASN1_CONSTRUCTED) == ASN1_CHOICE_0) {
	entry = dataStart(current, size, &entrySize, false);
	if (entry == NULL) return;
	tagSize = entry - current;
	current += tagSize + entrySize;
	size -= tagSize + entrySize;
	tokenName = (char *)malloc(entrySize+1);
	if (tokenName) {
	    memcpy(tokenName, entry, entrySize);
	    tokenName[entrySize] = 0;
	}
    }

    /* parsing flags */
#ifdef notdef
    /* we arn't using this right now, keep it for future reference */
    if (current[0] == ASN1_BIT_STRING) {
    /* recordinfo parsing would go here */
	unsigned long bits;
	entry = dataStart(current, size, &entrySize, false);
	if (entry == NULL) return;
	tagSize = entry - current;
	current += tagSize + entrySize;
	size -= tagSize + entrySize;
	bits = GetBits(entry, entrySize,8,2);
    }
#endif
    return;
}
