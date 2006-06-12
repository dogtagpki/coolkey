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

#ifndef CKY_BASE_H
#define CKY_BASE_H 1

/*
 * Common types and structs
 */
/* buffer sizes */
typedef unsigned long CKYSize;
/* offsets into buffers are data */
typedef unsigned long CKYOffset;
/* bytes, buffers */
typedef unsigned char CKYByte;
/* Bool type */
typedef unsigned char CKYBool;

#define CKYBUFFER_PUBLIC \
    unsigned long reserved1;\
    unsigned long reserved2;\
    void *reserved3;\
    void *reserved4;

#define CKYAPDU_PUBLIC \
    unsigned long reserved1;\
    unsigned long reserved2;\
    void *reserved3;\
    void *reserved4; \
    void *reserved5;


typedef struct _CKYBuffer {
#ifdef CKYBUFFER_PRIVATE
    CKYBUFFER_PRIVATE
#else
    CKYBUFFER_PUBLIC
#endif
} CKYBuffer;

typedef struct _CKYAPDU {
#ifdef CKYAPDU_PRIVATE
    CKYAPDU_PRIVATE
#else
    CKYAPDU_PUBLIC
#endif
} CKYAPDU;

/*
 * the following is just to make sure the sizes match 
 */
#ifdef DEBUG
#ifdef CKYBUFFER_PRIVATE
typedef struct _CKYBufferPublic {
    CKYBUFFER_PUBLIC
} CKYBufferPublic;

typedef struct _CKYAPDUPublic {
    CKYAPDU_PUBLIC
} CKYAPDUPublic;
#endif
#endif

typedef enum {
    CKYSUCCESS,		/* operation completed successfully */
    CKYNOMEM,		/* failed to allocate memory */
    CKYDATATOOLONG,	/* index or length exceeded a buffer or device size */
    CKYNOSCARD,		/* Scard library does not exist */
    CKYSCARDERR,		/* I/O Error in the SCard interface level. */
			/* more specific error values can be queried from
			 * the context or connection with the 
			 * GetLastError() call */
    CKYLIBFAIL,		/* error is shared library. no additional 
			 * error is available. Only returned from internal
			 * SHlib calls (not surfaced in public APIs */
    CKYAPDUFAIL,		/* processing worked, but applet rejected the APDU
			 * (command) sent. ADPUIOStatus has more info on
			 * why the APDU failed */
    CKYINVALIDARGS,      /* Caller passed in bad args */
} CKYStatus;

/*
 * defines related to APDU's
 */
#define CKY_CLA_OFFSET	0
#define CKY_INS_OFFSET	1
#define CKY_P1_OFFSET	2
#define CKY_P2_OFFSET	3
#define CKY_P3_OFFSET	4 /* P3 is P3, LC, and LE depending on usage */
#define CKY_LC_OFFSET	4
#define CKY_LE_OFFSET	4

#define CKYAPDU_MAX_DATA_LEN	256
#define CKYAPDU_MIN_LEN		4
#define CKYAPDU_HEADER_LEN	5
#define CKYAPDU_MAX_LEN		(CKYAPDU_HEADER_LEN+CKYAPDU_MAX_DATA_LEN)
#define CKY_MAX_ATR_LEN		32
#define CKY_OUTRAGEOUS_MALLOC_SIZE (1024*1024)

/*
 * allow direct inclusion in C++ files 
 */
#ifdef __cplusplus
#define CKY_BEGIN_PROTOS extern "C" {
#define CKY_END_PROTOS }
#else
#define CKY_BEGIN_PROTOS 
#define CKY_END_PROTOS
#endif

CKY_BEGIN_PROTOS
/*
 * generic buffer management functions
 *
 * These functions allow simple buffer management used in the CoolKey
 * library and it's clients.
 */

/*
 * Init functions clobbers the current contents and allocates the required 
 * space. 
 *   - Active buffers should call CKYBuffer_FreeData before calling an init 
 * function.
 *   - New buffers should call some CKYBuffer_Init function before any use.
 *   - All init functions copies the supplied data into newly allocated space.
 */
/* Create an empty buffer with no memory allocated to it. This is sufficient
 * to begin using a buffer. Note that new calls will probably allocate memory.
 * It is safe to free an empty buffer. */
CKYStatus CKYBuffer_InitEmpty(CKYBuffer *buf);

/* Create a buffer of length len all initialized to '0' */
CKYStatus CKYBuffer_InitFromLen(CKYBuffer *buf, CKYSize len);

/* Create a buffer by decoding a hex string.  hexString is NULL terminated. */
CKYStatus CKYBuffer_InitFromHex(CKYBuffer *buf, const char *hexString);
	
/* Create a buffer from data */
CKYStatus CKYBuffer_InitFromData(CKYBuffer *buf, const CKYByte *data, CKYSize len);
    
/* Create a buffer from part of another buffer. Start indicates the
 * offset in the old buffer to start in, and len specifies how many bytes
 * to copy */
CKYStatus CKYBuffer_InitFromBuffer(CKYBuffer *buf, const CKYBuffer *src,
						 CKYOffset start, CKYSize len);
/* Create a buffer from an exact copy of another buffer */
CKYStatus CKYBuffer_InitFromCopy(CKYBuffer *buf, const CKYBuffer *src);
/*
 * append functions increase the buffer size if necessary
 */
/* append a short in applet order */
CKYStatus CKYBuffer_AppendChar(CKYBuffer *buf, CKYByte b);

/* append a short in applet order */
CKYStatus CKYBuffer_AppendShort(CKYBuffer *buf, unsigned short val);

/* append a long in applet order */
CKYStatus CKYBuffer_AppendLong(CKYBuffer *buf, unsigned long val);

/* append data. the data starts at data and extends len bytes */
CKYStatus CKYBuffer_AppendData(CKYBuffer *buf, const CKYByte *data, CKYSize len);

/* append buffer fragment. the data starts at buffer[offset] 
 * and extends len bytes */
CKYStatus CKYBuffer_AppendBuffer(CKYBuffer *buf, const CKYBuffer *src, 
						CKYOffset offset, CKYSize len);

/* append a full buffer  */
CKYStatus CKYBuffer_AppendCopy(CKYBuffer *buf, const CKYBuffer *src );

/* reserve increases the space allocated for the buffer, but does not
 * increase the actual buffer size. If the buffer already newSize or more
 * space allocated, Reserve is a no op.
 */
CKYStatus CKYBuffer_Reserve(CKYBuffer *buf, CKYSize newSize) ;

/* resize affects the buffer's size. If the buffer len increases,
 * the new date will be zero'ed out. If the buffer shrinks, the buffer
 * is truncated, but the space is not removed.
 */
CKYStatus CKYBuffer_Resize(CKYBuffer *buf, CKYSize newLen);

/* replace bytes starting at 'offset'. If the buffer needs to be extended,
 * it will be automatically */
CKYStatus CKYBuffer_Replace(CKYBuffer *buf, CKYOffset offset, const CKYByte *data, 
								CKYSize len);

/* set  byte at ofset. The buffer is extended to offset if necessary */
CKYStatus CKYBuffer_SetChar(CKYBuffer *buf, CKYOffset offset, CKYByte c);
/* set several copies of 'c' at from offset to offset+ len */
CKYStatus CKYBuffer_SetChars(CKYBuffer *buf, CKYOffset offset, 
						CKYByte c, CKYSize len);
/* These functions work in applet order */
CKYStatus CKYBuffer_SetShort(CKYBuffer *buf, CKYOffset offset, unsigned short val);
CKYStatus CKYBuffer_SetLong(CKYBuffer *buf, CKYOffset offset, unsigned long val);

/* read a character from offset. If offset is beyond the end of the buffer,
 * then the function returns '0' */
CKYByte CKYBuffer_GetChar(const CKYBuffer *buf, CKYOffset offset);
/* These functions work in applet order */
unsigned short CKYBuffer_GetShort(const CKYBuffer *buf, CKYOffset offset);
unsigned long CKYBuffer_GetLong(const CKYBuffer *buf, CKYOffset offset);

/* clear out all the data in a buffer */
void CKYBuffer_Zero(CKYBuffer *buf);

/* return the size (length) of a buffer. This is only the portion of the 
 * buffer that has valid data set. */
CKYSize CKYBuffer_Size(const CKYBuffer *buf);

/* return a pointer to the data buffer */
const CKYByte *CKYBuffer_Data(const CKYBuffer *buf);

/* compare two buffers  return :
 *  1 if the two buffers are equal,
 *  0 if they are not */
CKYBool CKYBuffer_IsEqual(const CKYBuffer *buf1, const CKYBuffer *buf2);
/* compares raw data with a buffer or equality */
CKYBool CKYBuffer_DataIsEqual(const CKYBuffer *buf1,
				 	const CKYByte *buf2, CKYSize buf2Len);

/* free all the data associated with a buffer and initialize the buffer */
CKYStatus CKYBuffer_FreeData(CKYBuffer *buf);

/*
 * APDU's are buffers that know about the APDU structure
 */
CKYStatus CKYAPDU_Init(CKYAPDU *apdu);
CKYStatus CKYAPDU_InitFromData(CKYAPDU *apdu, const CKYByte *data, CKYSize size);
CKYStatus CKYAPDU_FreeData(CKYAPDU *apdu);

/* Access APDU header bytes */
CKYByte CKYAPDU_GetCLA(const CKYAPDU *apdu);
CKYStatus CKYAPDU_SetCLA(CKYAPDU *apdu, CKYByte b);
CKYByte CKYAPDU_GetINS(const CKYAPDU *apdu);
CKYStatus CKYAPDU_SetINS(CKYAPDU *apdu, CKYByte b);
CKYByte CKYAPDU_GetP1(const CKYAPDU *apdu);
CKYStatus CKYAPDU_SetP1(CKYAPDU *apdu, CKYByte b);
CKYByte CKYAPDU_GetP2(const CKYAPDU *apdu);
CKYStatus CKYAPDU_SetP2(CKYAPDU *apdu, CKYByte b);

/* add sending date to the  APDU */
/* Set resets the buffer, append, adds the data to the end. Lc in
 * the APDU header is automaticallu updated */
CKYStatus CKYAPDU_SetSendData(CKYAPDU *apdu, const CKYByte *data, CKYSize len);
CKYStatus CKYAPDU_SetSendDataBuffer(CKYAPDU *apdu, const CKYBuffer *buf);
CKYStatus CKYAPDU_AppendSendData(CKYAPDU *apdu, const CKYByte *data, CKYSize len);
CKYStatus CKYAPDU_AppendSendDataBuffer(CKYAPDU *apdu, const CKYBuffer *buf);

/* set Le in the APDU header to the amount of bytes expected to be
 * returned. */
CKYStatus CKYAPDU_SetReceiveLen(CKYAPDU *apdu, CKYByte recvlen);

/* set the parent loadmodule name */
void CKY_SetName(char *name);

CKY_END_PROTOS
    
#endif /* CKY_BASE_H */
