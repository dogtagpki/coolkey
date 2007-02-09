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
#include "object.h"
#include <algorithm>

using std::find_if;


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
    : muscleObjID(muscleObjID_), handle(handle_), label(NULL), name(NULL)
{ 
    CKYBuffer_InitEmpty(&pubKey);
}

PKCS11Object::PKCS11Object(unsigned long muscleObjID_, const CKYBuffer *data,
    CK_OBJECT_HANDLE handle_) :  muscleObjID(muscleObjID_), handle(handle_),
			label(NULL), name(NULL)
{
    CKYBuffer_InitEmpty(&pubKey);

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
	delete label;
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
    unsigned int len;
} CCItem;

typedef enum {
    SECSuccess=0,
    SECFailure=1
} SECStatus;

static const CKYByte*
dataStart(const CKYByte *buf, unsigned int length,
                        unsigned int *data_length, bool includeTag) {
    unsigned char tag;
    unsigned int used_length= 0;

    tag = buf[used_length++];

    /* blow out when we come to the end */
    if (tag == 0) {
        return NULL;
    }

    *data_length = buf[used_length++];

    if (*data_length&0x80) {
        int  len_count = *data_length & 0x7f;

        *data_length = 0;

        while (len_count-- > 0) {
            *data_length = (*data_length << 8) | buf[used_length++];
        }
    }

    if (*data_length > (length-used_length) ) {
        *data_length = length-used_length;
        return NULL;
    }
    if (includeTag) *data_length += used_length;

    return (buf + (includeTag ? 0 : used_length));
}

static const CKYByte *
unwrapBitString(const CKYByte *buf, unsigned int len, unsigned int *retLen)
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
GetKeyFieldItems(const CKYByte *spki_data,unsigned int spki_length,
        CCItem *modulus, CCItem *exponent)
{
    const CKYByte *buf = spki_data;
    unsigned int buf_length = spki_length;
    const CKYByte*dummy;
    unsigned int dummylen;

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

Key::Key(unsigned long muscleObjID, const CKYBuffer *data,
    CK_OBJECT_HANDLE handle) : PKCS11Object(muscleObjID, data, handle)
{
    // infer key attributes
    CK_OBJECT_CLASS objClass = getClass();
    CKYBuffer empty;
    CKYBuffer_InitEmpty(&empty);

    if ((objClass == CKO_PUBLIC_KEY) || (objClass == CKO_PRIVATE_KEY)) {
	/* only CKK_RSA is supported */
	setAttributeULong(CKA_KEY_TYPE, CKK_RSA);
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
Key::completeKey(const PKCS11Object &cert)
{
    // infer key attributes from cert
    bool modulusExists, exponentExists;
    CKYBuffer modulus; CKYBuffer_InitEmpty(&modulus);
    CKYBuffer exponent; CKYBuffer_InitEmpty(&exponent);

    if (!attributeExists(CKA_LABEL)) {
	setAttribute(CKA_LABEL, cert.getAttribute(CKA_LABEL));
    }
    try {
 	modulusExists = attributeExists(CKA_MODULUS);
	exponentExists = attributeExists(CKA_PUBLIC_EXPONENT);
	if (!modulusExists || !exponentExists) {
	    const CKYBuffer *key = cert.getPubKey();
	    GetKeyFields(key, &modulus, &exponent);
	    if (!modulusExists) {
		setAttribute(CKA_MODULUS, &modulus);
	    }
	    if (!exponentExists) {
		setAttribute(CKA_PUBLIC_EXPONENT, &exponent);
	    }
	}
    } catch (PKCS11Exception &e) {
	CKYBuffer_FreeData(&modulus);
	CKYBuffer_FreeData(&exponent);
	throw e;
    }
    CKYBuffer_FreeData(&modulus);
    CKYBuffer_FreeData(&exponent);
}

static SECStatus
GetCertFieldItems(const CKYByte *dercert,unsigned int cert_length,
        CCItem *issuer, CCItem *serial, CCItem *derSN, CCItem *subject,
        CCItem *valid, CCItem *subjkey)
{
    const CKYByte *buf;
    unsigned int buf_length;
    const CKYByte*dummy;
    unsigned int dummylen;

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

    setAttributeBool(CKA_DECRYPT, decrypt);
    setAttributeBool(CKA_SIGN, !decrypt);
    setAttributeBool(CKA_SIGN_RECOVER, !decrypt);
    setAttributeBool(CKA_UNWRAP, FALSE);
    setAttributeBool(CKA_SENSITIVE, TRUE);
    setAttributeBool(CKA_EXTRACTABLE, FALSE);

    CKYBuffer modulus; CKYBuffer_InitEmpty(&modulus);
    CKYBuffer exponent; CKYBuffer_InitEmpty(&exponent);

    try {
	const CKYBuffer *key = cert.getPubKey();
	GetKeyFields(key, &modulus, &exponent);
	setAttribute(CKA_MODULUS, &modulus);
	setAttribute(CKA_PUBLIC_EXPONENT, &exponent);
    } catch (PKCS11Exception &e) {
	CKYBuffer_FreeData(&modulus);
	CKYBuffer_FreeData(&exponent);
	throw e;
    }
    CKYBuffer_FreeData(&modulus);
    CKYBuffer_FreeData(&exponent);
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
    setAttributeULong(CKA_KEY_TYPE, CKK_RSA);

    setAttributeBool(CKA_ENCRYPT, encrypt);
    setAttributeBool(CKA_VERIFY, !encrypt);
    setAttributeBool(CKA_VERIFY_RECOVER, !encrypt);
    setAttributeBool(CKA_WRAP, FALSE);

    CKYBuffer modulus; CKYBuffer_InitEmpty(&modulus);
    CKYBuffer exponent; CKYBuffer_InitEmpty(&exponent);

    try {
	const CKYBuffer *key = cert.getPubKey();
	GetKeyFields(key, &modulus, &exponent);
	setAttribute(CKA_MODULUS, &modulus);
	setAttribute(CKA_PUBLIC_EXPONENT, &exponent);
    } catch (PKCS11Exception &e) {
	CKYBuffer_FreeData(&modulus);
	CKYBuffer_FreeData(&exponent);
	throw e;
    }
    CKYBuffer_FreeData(&modulus);
    CKYBuffer_FreeData(&exponent);
}

static const char *CAC_Label[] = {
	"CAC ID Certificate",
	"CAC Email Signature Certificate",
	"CAC Email Encryption Certificate",
};

static const unsigned char CN_DATA[] = { 0x55, 0x4, 0x3 };
const unsigned int CN_LENGTH = sizeof(CN_DATA);

static SECStatus
GetCN(const CKYByte *dn, unsigned int dn_length, CCItem *cn)
{
    const CKYByte *buf;
    unsigned int buf_length;

    /* unwrap the sequence */
    buf = dataStart(dn,dn_length,&buf_length, false);
    if (buf == NULL) return SECFailure;

    while (buf_length) {
	const CKYByte *name;
	unsigned int name_length;
	const CKYByte *oid;
	unsigned int oid_length;

	/* unwrap the set */
	name = dataStart(buf, buf_length, &name_length, false);

        /* advance to next set */
	buf_length -= (name-buf) + name_length;
	buf = name + name_length; 

	/* unwrap the Sequence */
	name = dataStart(name, name_length, &name_length, false);

        /* unwrap the oid */
	oid = dataStart(name, name_length, &oid_length, false);

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
    CK_BBOOL decrypt = FALSE;

    /* So we know what the key is supposed to be used for based on
     * the instance */
    if (instance == 2) {
	decrypt = TRUE;
    }

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
