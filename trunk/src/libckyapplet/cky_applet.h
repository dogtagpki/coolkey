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

#ifndef CKY_APPLET_H
#define CKY_APPLET_H 1

#include "cky_base.h"
#include "cky_card.h"
#include "cky_factory.h"

/*
 * base typdefs
 */
/*
 * ISO and applet response codes. 
 */
typedef unsigned short CKYISOStatus; /* applet return status */
/* Psuedo return codes created by the library software */
#define CKYISO_INVRESPONSE	    0xffff  /* code returned by library to 
					     * indicate  no valid response 
					     * received */
#define CKYISO_NORESPONSE	    0x0000  /* code returned by the library if
					     * operation failed before 
					     * attempting to read a response */
/* ISO defined Return codes */
#define CKYISO_SUCCESS		    0x9000  /* SUCCESS! */
#define CKYISO_MORE_MASK	    0xff00  /* More data mask */
#define CKYISO_MORE		    0x6300  /* More data available */
#define CKYISO_DATA_INVALID	    0x6984
/* Applet Defined Return codes */
#define CKYISO_NO_MEMORY_LEFT        0x9c01  /* There have been memory 
                                             * problems on the card */
#define CKYISO_AUTH_FAILED	    0x9c02  /* Entered PIN is not correct */
#define CKYISO_OPERATION_NOT_ALLOWED 0x9c03  /* Required operation is not 
					     * allowed in actual 
					     * circumstances */
#define CKYISO_UNSUPPORTED_FEATURE   0x9c05  /* Required feature is not (yet) 
                                             * supported */
#define CKYISO_UNAUTHORIZED          0x9c06  /* Required operation was not 
					     * authorized because of a lack of 
					     * privileges */
#define CKYISO_OBJECT_NOT_FOUND      0x9c07  /* Required object is missing */
#define CKYISO_OBJECT_EXISTS         0x9c08  /* New object ID already in use */
#define CKYISO_INCORRECT_ALG         0x9c09  /* Algorithm specified is not 
					     * correct */
#define CKYISO_SIGNATURE_INVALID     0x9c0b  /* Verify operation detected an 
					     * invalid signature */
#define CKYISO_IDENTITY_BLOCKED	    0x9c0c  /* Operation has been blocked for 
					     * security reason */
#define CKYISO_INVALID_PARAMETER     0x9c0f  /* Invalid input parameter to 
					     * command */
#define CKYISO_INCORRECT_P1          0x9c10  /* Incorrect P1 parameter */
#define CKYISO_INCORRECT_P2          0x9c11  /* Incorrect P2 parameter */
#define CKYISO_SEQUENCE_END	    0x9c12  /* No more data available */
#define CKYISO_INTERNAL_ERROR        0x9cff  /* Reserved for debugging, 
					     * shouldn't happen */

/*
 * Pin Constants as used by our applet
 */
#define CKY_OLD_USER_PIN_NUM	1  /* version 0 and earlier */
#define CKY_USER_PIN_NUM		0

/*
 * special size that tells the Verify Function not to verify the size because
 * the ADPU can return variable size.
 */
#define CKY_SIZE_UNKNOWN		0xffffffff

/*
 * structures for returning Applet responses
 */
typedef struct _CKYAppletRespGetStatus {
    CKYByte	protocolMajorVersion;
    CKYByte	protocolMinorVersion;
    CKYByte	appletMajorVersion;
    CKYByte	appletMinorVersion;
    unsigned long totalObjectMemory;
    unsigned long freeObjectMemory;
    CKYByte	numberPins;
    CKYByte	numberKeys;
    unsigned short loggedInMask;
} CKYAppletRespGetStatus;

typedef struct _CKYAppletRespGetLifeCycleV2 {
    CKYByte	lifeCycle;
    CKYByte	pinCount;
    CKYByte	protocolMajorVersion;
    CKYByte	protocolMinorVersion;
} CKYAppletRespGetLifeCycleV2;

typedef struct _CKYAppletRespGetBuiltinACL {
    unsigned short	create_object_ACL;
    unsigned short	create_key_ACL;
    unsigned short	create_pin_ACL;
    CKYByte	enable_ACL_change;
} CKYAppletRespGetBuiltinACL;

typedef struct _CKYAppletRespGetCPLCData {
    unsigned short	CPLCtag;
    CKYByte		length;
    unsigned short	fabricator;
    unsigned short	romType;
    unsigned short	romOSID;
    unsigned short	romOSDate;
    unsigned short	romOSLevel;
    unsigned short	eepromFabricationDate;
    unsigned long	eepromSerialNumber;
    unsigned short	eepromBatchID;
    unsigned short	eepromModuleFabricator;
    unsigned short	eepromModuleDate;
    unsigned short	eepromICManufacturer;
    unsigned short	eepromEmbeddingDate;
    unsigned short	eepromPrePersonalizer;
    unsigned short	eepromPrePersonalizeDate;
    unsigned long	eepromPrePersonalizeID;
    unsigned short	eepromPersonalizer;
    unsigned short	eepromPersonalizeDate;
    unsigned long	eepromPersonalizeID;
} CKYAppletRespGetCPLCData;

typedef struct _CKYAppletRespListObjects {
    unsigned long  objectID;
    CKYSize         objectSize;
    unsigned short readACL;
    unsigned short writeACL;
    unsigned short deleteACL;
} CKYAppletRespListObjects;

typedef struct _CKYAppletRespListKeys {
    CKYByte         keyNum;
    CKYByte         keyType;
    CKYByte         keyPartner;
    unsigned short keySize;
    unsigned short readACL;
    unsigned short writeACL;
    unsigned short useACL;
} CKYAppletRespListKeys;

/*
 * structures for the generic factories
 */
typedef struct _CKYAppletArgCreatePIN {
    const char *pinValue;
    CKYByte pinNumber;
    CKYByte maxAttempts;
} CKYAppletArgCreatePIN;

typedef struct _CKYAppletArgVerifyPIN {
    const char *pinValue;
    CKYByte pinNumber;
} CKYAppletArgVerifyPIN;

typedef struct _CKYAppletArgChangePIN {
    const char *oldPin;
    const char *newPin;
    CKYByte pinNumber;
} CKYAppletArgChangePIN;

typedef struct _CKYAppletArgCreateObject {
    unsigned long  objectID;
    CKYSize         size;
    unsigned short readACL;
    unsigned short writeACL;
    unsigned short deleteACL;
} CKYAppletArgCreateObject;

typedef struct _CKYAppletArgDeleteObject {
    unsigned long  objectID;
    CKYByte         zero;
} CKYAppletArgDeleteObject;

typedef struct _CKYAppletArgReadObject {
    unsigned long  objectID;
    CKYOffset       offset;
    CKYByte         size;
} CKYAppletArgReadObject;

typedef struct _CKYAppletArgComputeCrypt {
    CKYByte   keyNumber;
    CKYByte   mode;
    CKYByte   direction;
    CKYByte   location;
    const CKYBuffer *data;
    const CKYBuffer *sig;
} CKYAppletArgComputeCrypt;

/* fills in an APDU from a structure -- form of all the generic factories*/
typedef CKYStatus (*CKYAppletFactory)(CKYAPDU *apdu, const void *param);
/* fills in an a structure from a response -- form of all the fill structures*/
typedef CKYStatus (*CKYFillFunction)(const CKYBuffer *response, 
						CKYSize size, void *param);

CKY_BEGIN_PROTOS
/*****************************************************************
 * 
 * Generic factorys are used by the generic APDU processing
 * to customize the formatting of APDU. The all have the same signature
 * as CKYAppletFactory.  Typically APDUs are formatted
 * using parameterized calls of the form CKYAPDUFactory_ADPUNAME.
 * The generic processing code, however needs calls with a common
 * Signature. To accomplish the conversion, we build generic versions
 * which take a void * parameter. Trivial APDU's can pass NULL or a pointer
 * to the single parameter that they need. More complicated APDU's use
 * CKYAppletArg* data structures defined above to pass more arguments.
 *
 * Generic factorys then call the standard CKYAPDUFactor_ADPUNAME() functions
 * to build the APDUs. These functions are intended only as arguments
 * to the generic ADPU calls, and not to be called directly.
 *
 *****************************************************************/
/* param == CKYBuffer * (AID) */
CKYStatus CKYAppletFactory_SelectFile(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_SelectCardManager(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetCPLCData(CKYAPDU *apdu, const void *param);
/* param == CKYByte * (pointer to seq) */
CKYStatus CKYAppletFactory_ListKeys(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgComputeCrypt */
CKYStatus CKYAppletFactory_ComputeCryptInit(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgComputeCrypt */
CKYStatus CKYAppletFactory_ComputeCryptProcess(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgComputeCrypt */
CKYStatus CKYAppletFactory_ComputeCryptFinal(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgCreatePIN */
CKYStatus CKYAppletFactory_CreatePIN(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgVeriryPIN */
CKYStatus CKYAppletFactory_VerifyPIN(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgChangePIN */
CKYStatus CKYAppletFactory_ChangePIN(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_ListPINs(CKYAPDU *apdu, const void *param);
/* param == CKYByte * (pointer to pinNumber) */
CKYStatus CKYAppletFactory_Logout(CKYAPDU *apdu, const void *param);
/* Future add WriteObject */
/* param == CKYAppletArgCreateObject */
CKYStatus CKYAppletFactory_CreateObject(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgDeleteObject */
CKYStatus CKYAppletFactory_DeleteObject(CKYAPDU *apdu, const void *param);
/* param == CKYAppletArgReadObject */
CKYStatus CKYAppletFactory_ReadObject(CKYAPDU *apdu, const void *param);
/* param == CKYByte * (pointer to seq) */
CKYStatus CKYAppletFactory_ListObjects(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetStatus(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_Noop(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetBuildID(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetLifeCycle(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetLifeCycleV2(CKYAPDU *apdu, const void *param);
/* param == CKYByte * */
CKYStatus CKYAppletFactory_GetRandom(CKYAPDU *apdu, const void *param);
/* param == CKY_Buffer */
CKYStatus CKYAppletFactory_SeedRandom(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetIssuerInfo(CKYAPDU *apdu, const void *param);
/* param == NULL */
CKYStatus CKYAppletFactory_GetBuiltinACL(CKYAPDU *apdu, const void *param);
/*  deprecates 0.x functions */
/* param == NULL */
CKYStatus CKYAppletFactory_LogoutAllV0(CKYAPDU *apdu, const void *param);

/*****************************************************************
 *
 * Generic Fill routines used by the generic APDU processing
 * to customize how the response data is returned to the application.
 * generally the param points to some structure which is filled in
 * by the Fill function from the response data. Each APDU command
 * can potentially have it's own fill function. Different appearent
 * functions can be accomplished by calling the same APDU with a different
 * fill function. The fill functions below are considered globally interesting
 * to applications that wish to make custom APDU calls using the
 * applet generic processing. Fill functions are never called directly,
 * but through callback, and all have the same signature (CKYFillFunction)
 * 
 *****************************************************************/
/* a null fill function for those APDU's which do not return data */
CKYStatus CKYAppletFill_Null(const CKYBuffer *response, CKYSize size, void *param);
/* Buffer Fills: */
/* Replace fill function for those APDU's which return raw data */
/* param == CKYBuffer * */
CKYStatus CKYAppletFill_ReplaceBuffer(const CKYBuffer *response, CKYSize size, 
								void *param);
/* Append fill function can be used with any APDU that uses Buffer
 * Replace. Repeated calls continuously adds more data to the buffer. 
 * Useful for repeated operations like read.  */ 
/* param == CKYBuffer * */
CKYStatus CKYAppletFill_AppendBuffer(const CKYBuffer *response,
						 CKYSize size, void *param);
/* Single value fills: Byte, Short, & Long */
/* param == CKYByte * */
CKYStatus CKYAppletFill_Byte(const CKYBuffer *response, CKYSize size, void *param);
/* param == CKYByte * */
CKYStatus CKYAppletFill_Short(const CKYBuffer *response, CKYSize size, void *param);
CKYStatus CKYAppletFill_Long(const CKYBuffer *response, CKYSize size, void *param);

/*****************************************************************
 *
 * Utilities shared by all the fetch Cards.
 * 
 *****************************************************************/
/* 
 * verify the we got a successful response. Responses should include
 * the expected data returned plus a 2 byte return code. This return
 * code should be 0x9000 on success. The function copies the return code
 * to apduRC if apduRC is not NULL.
 */
CKYBool CKYApplet_VerifyResponse(const CKYBuffer *response, CKYSize dataSize, 
						    CKYISOStatus *apduRC);
/*
 * most commands have identical operations. This function
 * handles these operations, isolating  the differences in
 * call back functions.
 *   It creates the ADPU using afFunc with afArg.
 *   Adds nonce if it exists.
 *   Sends the ADPU to the card through the connection conn.
 *   Checks that the response was valid (returning the responce code in apduRC.
 *   Formats the response data into fillArg with fillFunc
 * nonce and apduRC can be NULL (no nonce is added, not status returned 
 * legal values for afArg are depened on afFunc.
 * legal values for fillArg are depened on fillFunc.
 */
CKYStatus CKYApplet_HandleAPDU(CKYCardConnection *conn,
 		CKYAppletFactory afFunc, const void *afArg, 
		const CKYBuffer *nonce, CKYSize size,
		CKYFillFunction fillFunc, void *fillArg, CKYISOStatus *apduRC);


/*****************************************************************
 *
 *  The following convience functions convert APDU calls
 *   into function calls, with input and output parameters.
 *   The application is still responsible for 
 *      1) creating a connection to the card, 
 *      2) Getting a tranaction long,  then
 *      3) selecting  the appropriate applet (or Card manager). 
 *   Except for those calls that have been noted, the appropriate applet 
 *   is the CoolKey applet.
 * 
 *****************************************************************/
/* Select an applet. Can happen with either applet selected */
CKYStatus CKYApplet_SelectFile(CKYCardConnection *conn, const CKYBuffer *AID,
							 CKYISOStatus *apduRC);

/* Select the CoolKey applet. Special case of the above command */
/* Can happen with either applet selected */
CKYStatus CKYApplet_SelectCoolKeyManager(CKYCardConnection *conn,
							CKYISOStatus *apduRC);

/* Select the card manager.  Can happen with either applet selected */
CKYStatus CKYApplet_SelectCardManager(CKYCardConnection *conn, 
							CKYISOStatus *apduRC);
/* GetCPLC data -- must be called with CM selected */
/* fills in cplc */
CKYStatus CKYApplet_GetCPLCData(CKYCardConnection *conn, 
		CKYAppletRespGetCPLCData *cplc, CKYISOStatus *apduRC);
/* Get CUID.  -- must be called with CM selected */
/* special case of GetCPLCData */
/* fills in cuid */
CKYStatus CKYApplet_GetCUID(CKYCardConnection *conn, 
					CKYBuffer *cuid, CKYISOStatus *apduRC);
/* Get MSN. -- must be called with CM selected */
/* special case of GetCPLCData */
/* returns msn */
CKYStatus CKYApplet_GetMSN(CKYCardConnection *conn, unsigned long *msn,
							 CKYISOStatus *apduRC);

/* List Keys -- see applet documentation */
CKYStatus CKYApplet_ListKeys(CKYCardConnection *conn, CKYByte seq,
		CKYAppletRespListKeys *lkp, CKYISOStatus *apduRC);
/*
 * Compute Crypt Cluster.
 *
 * Compute Crypt takes 3 phases: Init, Process, Final.
 *  Applications can call each phase separately using:
 *    CKYApplet_ComputeCryptInit
 *    CKYApplet_ComputeCryptProcess
 *    CKYApplet_ComputeCryptFinal
 *  or call all three in one set with:
 *    CKYApplet_ComputeCrypt
 * Buffer values passed to Compute crypt should be raw data.
 * The helper functions format the 2 byte length data required by the
 * applet automatically.
 */
CKYStatus CKYApplet_ComputeCryptInit(CKYCardConnection *conn, CKYByte keyNumber, 
	CKYByte mode, CKYByte direction, CKYByte location,
				const CKYBuffer *nonce, CKYISOStatus *apduRC);
CKYStatus CKYApplet_ComputeCryptProcess(CKYCardConnection *conn, CKYByte keyNumber, 
	CKYByte location, const CKYBuffer *data, const CKYBuffer *nonce,
							 CKYISOStatus *apduRC);
CKYStatus CKYApplet_ComputeCryptFinal(CKYCardConnection *conn, CKYByte keyNumber, 
    CKYByte location, const CKYBuffer *data, CKYBuffer *sig, CKYBuffer *result,
				const CKYBuffer *nonce, CKYISOStatus *apduRC);
/**  ...look to data size to see if we should read/write the data to
 *  the on card buffer. (future) */
CKYStatus CKYApplet_ComputeCrypt(CKYCardConnection *conn, CKYByte keyNumber, 
    CKYByte mode, CKYByte direction, const CKYBuffer *data, CKYBuffer *sig,
	 	CKYBuffer *result, const CKYBuffer *nonce, CKYISOStatus *apduRC);
/* Pin Command -- see applet documentation for use */
CKYStatus CKYApplet_CreatePIN(CKYCardConnection *conn, CKYByte pinNumber, 
   			CKYByte maxAttempts, const char *pinValue, 
				const CKYBuffer *nonce, CKYISOStatus *apduRC);
CKYStatus CKYApplet_VerifyPIN(CKYCardConnection *conn, CKYByte pinNumber, 
		const char *pinValue, CKYBuffer *nonce, CKYISOStatus *apduRC);
CKYStatus CKYApplet_ChangePIN(CKYCardConnection *conn, const char *oldPin, 
   	 	const char *newPin, const CKYBuffer *nonce, 
		CKYISOStatus *apduRC);
CKYStatus CKYApplet_ListPINs(CKYCardConnection *conn,  unsigned short *pins,
						CKYISOStatus *apduRC);
CKYStatus CKYApplet_Logout(CKYCardConnection *conn, CKYByte pinNumber, 
				const CKYBuffer *nonce, CKYISOStatus *apduRC);
/* Object Commands -- see applet documentation for use */
CKYStatus CKYApplet_CreateObject(CKYCardConnection *conn, unsigned long objectID,
	CKYSize size, unsigned short readACL, unsigned short writeACL,
	unsigned short deleteACL, const CKYBuffer *nonce, CKYISOStatus *apduRC);
CKYStatus CKYApplet_DeleteObject(CKYCardConnection *conn, unsigned long objectID,
	CKYByte zero, const CKYBuffer *nonce, CKYISOStatus *apduRC);

/* CAC commands */
/* Select one of the CAC PKI applets. Special case of CKYApplet_SelectFile */
/* Select the CAC card manager.  Can happen with either applet selected */
CKYStatus CACApplet_SelectCardManager(CKYCardConnection *conn, 
							CKYISOStatus *apduRC);
/* Can happen with either applet selected */
CKYStatus CACApplet_SelectPKI(CKYCardConnection *conn, CKYByte instance,
			      CKYISOStatus *apduRC);
/* must happen with PKI applet selected */
CKYStatus CACApplet_SignDecrypt(CKYCardConnection *conn, const CKYBuffer *data,
		CKYBuffer *result, CKYISOStatus *apduRC);
CKYStatus CACApplet_GetCertificate(CKYCardConnection *conn, CKYBuffer *cert,
				   CKYISOStatus *apduRC);
CKYStatus CACApplet_GetCertificateFirst(CKYCardConnection *conn, 
				   CKYBuffer *cert, CKYSize *nextSize,
				   CKYISOStatus *apduRC);
CKYStatus CACApplet_GetCertificateAppend(CKYCardConnection *conn, 
				   CKYBuffer *cert, CKYSize nextSize,
				   CKYISOStatus *apduRC);

/*CKYStatus CACApplet_GetProperties(); */
CKYStatus CACApplet_VerifyPIN(CKYCardConnection *conn, const char *pin,
				   CKYISOStatus *apduRC);

/*
 * There are 3 read commands:
 *  
 * CKYApplet_ReadObject issues a single Read APDU call. Supplied data buffer
 *  is overwritten. This function is limited to reading 240 bytes.
 * CKYApplet_ReadObjectAppend also issues a single Read APDU call. However,
 *  the result is appended to the data buffer. Again, this function is limited
 *  to reading 240 bytes.
 * CKYApplet_ReadObjectFull can read an entire data object. It makes multiple
 *  apdu calls in order to read the full amount into the buffer. The buffer
 *  is overwriten.
 */
CKYStatus CKYApplet_ReadObject(CKYCardConnection *conn, unsigned long objectID,
		CKYOffset offset, CKYByte size, const CKYBuffer *nonce,
		CKYBuffer *data, CKYISOStatus *apduRC);

CKYStatus CKYApplet_ReadObjectAppend(CKYCardConnection *conn, 
	unsigned long objectID, CKYOffset offset, CKYByte size, 
	const CKYBuffer *nonce, CKYBuffer *data, CKYISOStatus *apduRC);
CKYStatus CKYApplet_ReadObjectFull(CKYCardConnection *conn, 
		unsigned long objectID, CKYOffset offset, CKYSize size,
		 const CKYBuffer *nonce, CKYBuffer *data, CKYISOStatus *apduRC);
CKYStatus CKYApplet_ListObjects(CKYCardConnection *conn, CKYByte seq,
		CKYAppletRespListObjects *lop, CKYISOStatus *apduRC);
CKYStatus CKYApplet_GetStatus(CKYCardConnection *conn, 
		CKYAppletRespGetStatus *status, CKYISOStatus *apduRC);
CKYStatus CKYApplet_Noop(CKYCardConnection *conn, CKYISOStatus *apduRC);
CKYStatus CKYApplet_GetBuildID(CKYCardConnection *conn, unsigned long *buildID,
						CKYISOStatus *apduRC);
CKYStatus CKYApplet_GetLifeCycle(CKYCardConnection *conn, CKYByte *personalized, 
							CKYISOStatus *apduRC);
CKYStatus CKYApplet_GetLifeCycleV2(CKYCardConnection *conn,
	 	CKYAppletRespGetLifeCycleV2 *ext, CKYISOStatus *apduRC);

CKYStatus CKYApplet_GetRandom(CKYCardConnection *conn,
	 	CKYBuffer *buf, CKYByte len, CKYISOStatus *apduRC);

CKYStatus CKYApplet_GetRandomAppend(CKYCardConnection *conn,
	 	CKYBuffer *buf, CKYByte len, CKYISOStatus *apduRC);

CKYStatus CKYApplet_SeedRandom(CKYCardConnection *conn,
	 	const CKYBuffer *buf, CKYISOStatus *apduRC);

CKYStatus CKYApplet_GetIssuerInfo(CKYCardConnection *conn,
	 	CKYBuffer *buf, CKYISOStatus *apduRC);

CKYStatus CKYApplet_GetBuiltinACL(CKYCardConnection *conn,
	 	CKYAppletRespGetBuiltinACL *gba, CKYISOStatus *apduRC);


/*
 * deprecates 0.x functions
 */
/* old applet verify pin call (no nonce returned) */
CKYStatus CKYApplet_VerifyPinV0(CKYCardConnection *conn, CKYByte pinNumber, 
			const char *pinValue, CKYISOStatus *apduRC);
/* logout all */
CKYStatus CKYApplet_LogoutAllV0(CKYCardConnection *conn, CKYISOStatus *apduRC);

CKY_END_PROTOS
#endif /* CKY_APPLET_H */
