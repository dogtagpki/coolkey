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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "cky_basei.h"
#include "cky_base.h"
#include "dynlink.h"

/*
 * generic buffer management functions
 *
 * These functions allow simple buffer management used in the CoolKey
 * library and it's clients.
 */

/* initialize a new buffer to a known state */
static void
ckyBuffer_initBuffer(CKYBuffer *buf)
{
#ifdef DEBUG
    assert(sizeof(CKYBuffer) == sizeof(CKYBufferPublic));
#endif
    buf->data = NULL;
    buf->size = 0;
    buf->len = 0;
} 

/*
 * Init functions clobbers the current contents and allocates the required 
 * space. Active buffers should call CKYBuffer_FreerData before
 * calling an init function. All init functions copies the supplied data
 * into newly allocated space.
 */
/* init an empty buffer that will later be filled in. */
CKYStatus
CKYBuffer_InitEmpty(CKYBuffer *buf)
{
   ckyBuffer_initBuffer(buf);
   return CKYSUCCESS;
}

/* Create a buffer of length len all initialized to '0' */
CKYStatus
CKYBuffer_InitFromLen(CKYBuffer *buf, CKYSize len)
{
    CKYStatus ret;

    ckyBuffer_initBuffer(buf);
    ret = CKYBuffer_Reserve(buf, len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->len = len;
    memset(buf->data, 0, buf->len);
    return CKYSUCCESS;
}

static CKYByte 
fromHex(const char *cp)
{
    if (*cp >= '0' && *cp <= '9') {
	return (CKYByte) *cp - '0';
    }
    if (*cp >= 'a' && *cp <= 'f') {
	return (CKYByte) *cp - 'a' + 0xa;
    }
    if (*cp >= 'A' && *cp <= 'F') {
	return (CKYByte) *cp - 'A' + 0xA;
    }
    return 0;
}

/* Create a buffer by decoding a hex string.  hexString is NULL terminated. */
CKYStatus
CKYBuffer_InitFromHex(CKYBuffer *buf, const char *hexString)
{
    int len = strlen(hexString);
    int dataHalf = 0;
    CKYByte lastDigit = 0;
    CKYByte digit;
    const char *cp;
    CKYByte *bp;
    CKYStatus ret;

    if (len & 1) {
	len++;
	dataHalf++;
    }
    ckyBuffer_initBuffer(buf);
    ret = CKYBuffer_Reserve(buf, len/2);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->len = len/2;
    bp = buf->data;
    for (cp = hexString; *cp; cp++) {
	digit = fromHex(cp);
	/* check for error? */
	if (dataHalf) {
	  *bp++= lastDigit << 4 | digit;
	}
	dataHalf ^= 1;
	lastDigit = digit;
    }
    return CKYSUCCESS;
}
	
/* Create a buffer from data */
CKYStatus
CKYBuffer_InitFromData(CKYBuffer *buf, const CKYByte *data, CKYSize len)
{
    CKYStatus ret;

    ckyBuffer_initBuffer(buf);
    ret = CKYBuffer_Reserve(buf, len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->len = len;
    memcpy(buf->data, data, buf->len);
    return CKYSUCCESS;
}
    

/* Create a buffer from part of another buffer. Start indicates the
 * offset in the old buffer to start in, and len specifies how many bytes
 * to copy */
CKYStatus
CKYBuffer_InitFromBuffer(CKYBuffer *buf, 
		const CKYBuffer *src, CKYOffset start, CKYSize len)
{
    CKYStatus ret;

    ckyBuffer_initBuffer(buf);
    if (src->len < start) {
	len = 0;
    } else if (src->len < start+len) {
	len = src->len -start;
    }
    ret = CKYBuffer_Reserve(buf, len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->len = len;
    if (len == 0) {
	return CKYSUCCESS;
    }
    memcpy(buf->data, src->data+start, buf->len);
    return CKYSUCCESS;
}

/* Create a buffer from and exact copy of another buffer. */
CKYStatus
CKYBuffer_InitFromCopy(CKYBuffer *buf, const CKYBuffer *src)
{
    CKYStatus ret;

    ckyBuffer_initBuffer(buf);
    /* src buffer has no length, make sure the dest is empty */
    if (src->len == 0) {
	return CKYSUCCESS;
    }
    ret = CKYBuffer_Reserve(buf, src->len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->len = src->len;
    memcpy(buf->data, src->data, buf->len);
    return CKYSUCCESS;
}

/*
 * append functions increase the buffer size if necessary
 */
CKYStatus
CKYBuffer_AppendChar(CKYBuffer *buf, CKYByte val)
{
    CKYStatus ret;

    ret = CKYBuffer_Reserve(buf, buf->len + 1);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->data[buf->len] = val;
    buf->len += 1;
    return CKYSUCCESS;
}

/* append a short in network order */
CKYStatus
CKYBuffer_AppendShort(CKYBuffer *buf, unsigned short val)
{
    CKYStatus ret;

    ret = CKYBuffer_Reserve(buf, buf->len + 2);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->data[buf->len+0] = (CKYByte) ((val >> 8) & 0xff);
    buf->data[buf->len+1] = (CKYByte) ((val >> 0) & 0xff);
    buf->len += 2;
    return CKYSUCCESS;
}

/* append a long in applet order */
CKYStatus
CKYBuffer_AppendLong(CKYBuffer *buf, unsigned long val)
{
    CKYStatus ret;

    ret = CKYBuffer_Reserve(buf, buf->len + 4);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    buf->data[buf->len+0] = (CKYByte) ((val >> 24) & 0xff);
    buf->data[buf->len+1] = (CKYByte) ((val >> 16) & 0xff);
    buf->data[buf->len+2] = (CKYByte) ((val >>  8) & 0xff);
    buf->data[buf->len+3] = (CKYByte) ((val >>  0) & 0xff);
    buf->len += 4;
    return CKYSUCCESS;
}

CKYStatus
CKYBuffer_Replace(CKYBuffer *buf, CKYOffset offset, const CKYByte *data, CKYSize len)
{
    CKYStatus ret;

    ret = CKYBuffer_Reserve(buf, offset+len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    if (buf->len < offset + len) {
	buf->len = offset + len;
    }
    memcpy(buf->data+offset, data, len);
    return CKYSUCCESS;
}

/* append data with length of len bytes */
CKYStatus
CKYBuffer_AppendData(CKYBuffer *buf, const CKYByte *data, CKYSize len)
{
    CKYStatus ret;

    ret = CKYBuffer_Reserve(buf, buf->len + len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    memcpy(buf->data+buf->len, data, len);
    buf->len += len;
    return CKYSUCCESS;
}

/* append data with length of len bytes */
CKYStatus
CKYBuffer_AppendBuffer(CKYBuffer *buf, const CKYBuffer *src, 
						CKYOffset offset, CKYSize len)
{
    unsigned long maxlen = src->len - offset;
    if ((maxlen < len) || (src->len < offset)) {
	return CKYDATATOOLONG;
    }
    return CKYBuffer_AppendData(buf, src->data+offset, len);
}

/* append data with length of len bytes */
CKYStatus
CKYBuffer_AppendCopy(CKYBuffer *buf, const CKYBuffer *src)
{
    return CKYBuffer_AppendData(buf, src->data, src->len);
}

CKYStatus 
CKYBuffer_Reserve(CKYBuffer *buf, CKYSize newSize)
{
    if (buf->size >= newSize) {
	return CKYSUCCESS;
    }
    buf->data = (CKYByte *)realloc(buf->data, newSize);
    if (buf->data == NULL) {
	buf->size = 0;
	buf->len = 0;
	return CKYNOMEM;
    }
    buf->size = newSize;
    return CKYSUCCESS;
}

CKYStatus
CKYBuffer_SetChar(CKYBuffer *buf, CKYOffset offset, CKYByte val)
{
    CKYStatus ret;

    if (buf->len < offset+1) {
	ret = CKYBuffer_Resize(buf,offset+1);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }
    buf->data[offset] = val;
    return CKYSUCCESS;
}

CKYStatus
CKYBuffer_SetChars(CKYBuffer *buf, CKYOffset offset, CKYByte val, CKYSize len)
{
    CKYStatus ret;

    if (buf->len < offset+len) {
	ret = CKYBuffer_Resize(buf,offset+len);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }
    memset(buf->data+offset,val, len);
    return CKYSUCCESS;
}

CKYStatus
CKYBuffer_SetShort(CKYBuffer *buf, CKYOffset offset, unsigned short val)
{
    CKYStatus ret;

    if (buf->len < offset+2) {
	ret = CKYBuffer_Resize(buf,offset+2);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }
    buf->data[offset+0] = (CKYByte) ((val >> 8) & 0xff);
    buf->data[offset+1] = (CKYByte) ((val >> 0) & 0xff);
    return CKYSUCCESS;
}

CKYStatus
CKYBuffer_SetLong(CKYBuffer *buf, CKYOffset offset, unsigned long val)
{
    CKYStatus ret;

    if (buf->len < offset+4) {
	ret = CKYBuffer_Resize(buf,offset+4);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
    }
    buf->data[offset+0] = (CKYByte) ((val >> 24) & 0xff);
    buf->data[offset+1] = (CKYByte) ((val >> 16) & 0xff);
    buf->data[offset+2] = (CKYByte) ((val >>  8) & 0xff);
    buf->data[offset+3] = (CKYByte) ((val >>  0) & 0xff);
    return CKYSUCCESS;
}

CKYByte
CKYBuffer_GetChar(const CKYBuffer *buf, CKYOffset offset)
{
    if (buf->len < offset+1) {
	return 0;
    }
    return buf->data[offset];
}

unsigned short
CKYBuffer_GetShort(const CKYBuffer *buf, CKYOffset offset)
{
    unsigned short val;
    if (buf->len < offset+2) {
	return 0;
    }
    val  = ((unsigned short)buf->data[offset+0]) << 8;
    val |= ((unsigned short)buf->data[offset+1]) << 0;
    return val;
}
	
unsigned long
CKYBuffer_GetLong(const CKYBuffer *buf, CKYOffset offset)
{
    unsigned long val;
    if (buf->len < offset+4) {
	return 0;
    }
    val  = ((unsigned long)buf->data[offset+0]) << 24;
    val |= ((unsigned long)buf->data[offset+1]) << 16;
    val |= ((unsigned long)buf->data[offset+2]) << 8;
    val |= ((unsigned long)buf->data[offset+3]) << 0;
    return val;
}
	
CKYStatus
CKYBuffer_Resize(CKYBuffer *buf, CKYSize newLen)
{
    CKYStatus ret;

    if (buf->len < newLen) {
	ret = CKYBuffer_Reserve(buf, newLen);
	if (ret != CKYSUCCESS) {
	    return ret;
	}
	memset(buf->data+buf->len, 0, newLen - buf->len);
    }
    buf->len = newLen;
    return CKYSUCCESS;
}

/* clear out a memory buffer... including unallocated space, then
 * set the buffer length to '0' */
void
CKYBuffer_Zero(CKYBuffer *buf)
{
    if (buf->size != 0) {
	memset(buf->data, 0, buf->size);
    }
    buf->len = 0;;
}

CKYSize
CKYBuffer_Size(const CKYBuffer *buf)
{
    return buf->len;
}

const CKYByte *
CKYBuffer_Data(const CKYBuffer *buf)
{
    return buf->data;
}

CKYBool
CKYBuffer_DataIsEqual(const CKYBuffer *buf1, const CKYByte *buf2, CKYSize buf2Len)
{
    if (buf1->len != buf2Len) {
	return 0;
    }

    /* all zero length buffers are equal, whether or not they have pointers
     * allocated */
    if (buf1->len == 0) {
	return 1;
    }

    return memcmp(buf1->data, buf2, buf1->len) == 0;
}

CKYBool
CKYBuffer_IsEqual(const CKYBuffer *buf1, const CKYBuffer *buf2)
{
    return CKYBuffer_DataIsEqual(buf1, buf2->data, buf2->len);
}

CKYStatus
CKYBuffer_FreeData(CKYBuffer *buf)
{
    free(buf->data);
    ckyBuffer_initBuffer(buf);
    return CKYSUCCESS;
}

CKYStatus
CKYAPDU_Init(CKYAPDU *apdu)
{
#ifdef DEBUG
    assert(sizeof(CKYAPDU) == sizeof(CKYAPDUPublic));
#endif
   ckyBuffer_initBuffer(&apdu->apduBuf);
   return CKYBuffer_Resize(&apdu->apduBuf, CKYAPDU_MIN_LEN);
}

CKYStatus
CKYAPDU_InitFromData(CKYAPDU *apdu, const CKYByte *data, CKYSize len)
{
#ifdef DEBUG
    assert(sizeof(CKYAPDU) == sizeof(CKYAPDUPublic));
#endif
    ckyBuffer_initBuffer(&apdu->apduBuf);
    if (len > CKYAPDU_MAX_DATA_LEN) {
	return CKYDATATOOLONG;
    }
    return CKYBuffer_InitFromData(&apdu->apduBuf, data, len);
}
   
CKYStatus
CKYAPDU_FreeData(CKYAPDU *apdu)
{
   return CKYBuffer_FreeData(&apdu->apduBuf);
}


CKYByte
CKYAPDU_GetCLA(const CKYAPDU *apdu)
{
    return CKYBuffer_GetChar(&apdu->apduBuf, CKY_CLA_OFFSET);
}

CKYStatus
CKYAPDU_SetCLA(CKYAPDU *apdu, CKYByte b)
{
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_CLA_OFFSET, b);
}

CKYByte
CKYAPDU_GetINS(const CKYAPDU *apdu) 
{
    return CKYBuffer_GetChar(&apdu->apduBuf, CKY_INS_OFFSET);
}

CKYStatus
CKYAPDU_SetINS(CKYAPDU *apdu, CKYByte b)
{
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_INS_OFFSET, b);
}

CKYByte
CKYAPDU_GetP1(const CKYAPDU *apdu)
{
    return CKYBuffer_GetChar(&apdu->apduBuf, CKY_P1_OFFSET);
}

CKYStatus
CKYAPDU_SetP1(CKYAPDU *apdu, CKYByte b)
{
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_P1_OFFSET, b);
}

CKYByte
CKYAPDU_GetP2(const CKYAPDU *apdu)
{
    return CKYBuffer_GetChar(&apdu->apduBuf, CKY_P2_OFFSET);
}

CKYStatus
CKYAPDU_SetP2(CKYAPDU *apdu, CKYByte b)
{
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_P2_OFFSET, b);
}

CKYStatus
CKYAPDU_SetSendData(CKYAPDU *apdu, const CKYByte *data, CKYSize len)
{
    CKYStatus ret;

    if (len > CKYAPDU_MAX_DATA_LEN) {
	return CKYDATATOOLONG;
    }

    ret = CKYBuffer_Resize(&apdu->apduBuf, len + CKYAPDU_HEADER_LEN);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    ret = CKYBuffer_SetChar(&apdu->apduBuf, CKY_LC_OFFSET,
				len == CKYAPDU_MAX_DATA_LEN ? 0: (CKYByte) len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    return CKYBuffer_Replace(&apdu->apduBuf, CKYAPDU_HEADER_LEN, data, len);
}

CKYStatus
CKYAPDU_SetSendDataBuffer(CKYAPDU *apdu, const CKYBuffer *buf)
{
    return CKYAPDU_SetSendData(apdu, buf->data,  buf->len);
}

CKYStatus
CKYAPDU_AppendSendData(CKYAPDU *apdu, const CKYByte *data, CKYSize len)
{
    CKYStatus ret;
    CKYSize dataLen;

    if (CKYBuffer_Size(&apdu->apduBuf) <= CKYAPDU_MIN_LEN) {
	return CKYAPDU_SetSendData(apdu,data, len);
    }

    dataLen = CKYBuffer_Size(&apdu->apduBuf) + len - CKYAPDU_HEADER_LEN;
    if (dataLen > CKYAPDU_MAX_DATA_LEN) {
	return CKYDATATOOLONG;
    }
    ret = CKYBuffer_AppendData(&apdu->apduBuf, data, len);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_LC_OFFSET,
			dataLen == CKYAPDU_MAX_DATA_LEN ? 0 : (CKYByte) dataLen);
}

CKYStatus
CKYAPDU_AppendSendDataBuffer(CKYAPDU *apdu, const CKYBuffer *buf)
{
    return CKYAPDU_AppendSendData(apdu, buf->data, buf->len);
}

CKYStatus
CKYAPDU_SetReceiveLen(CKYAPDU *apdu, CKYByte recvlen)
{
    CKYStatus ret;
    ret = CKYBuffer_Resize(&apdu->apduBuf, CKYAPDU_HEADER_LEN);
    if (ret != CKYSUCCESS) {
	return ret;
    }
    return CKYBuffer_SetChar(&apdu->apduBuf, CKY_LE_OFFSET, recvlen);
}

void
CKY_SetName(char *p)
{
}
    



