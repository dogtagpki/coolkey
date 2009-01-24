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

#ifndef CKY_FACTORY_H
#define CKY_FACTORY_H 1

#include "cky_base.h"

/*
 * Various Class bytes 
 */
#define CKY_CLASS_ISO7816 0x00
#define CKY_CLASS_GLOBAL_PLATFORM 0x80
#define CKY_CLASS_SECURE 0x84
#define CKY_CLASS_COOLKEY 0xb0

/*
 * Applet Instruction Bytes
 */
/* Card Manager */
#define CKY_INS_SELECT_FILE	0xa4
#define CKY_INS_GET_DATA 	0xca

/* deprecated */
#define CKY_INS_SETUP    	0x2A
#define CKY_INS_GEN_KEYPAIR	0x30
#define CKY_INS_EXPORT_KEY	0x34
#define CKY_INS_UNBLOCK_PIN	0x46
#define CKY_INS_GET_CHALLENGE	0x62
#define CKY_INS_CAC_EXT_AUTH	0x38
#define CKY_INS_LOGOUT_ALL	0x60

/* public */
#define CKY_INS_VERIFY_PIN	0x42
#define CKY_INS_LIST_OBJECTS	0x58
#define CKY_INS_LIST_KEYS	0x3A
#define CKY_INS_LIST_PINS	0x48
#define CKY_INS_GET_STATUS	0x3C
#define CKY_INS_GET_LIFECYCLE	0xF2
#define CKY_INS_GET_ISSUER_INFO	0xF6
#define CKY_INS_GET_BUILTIN_ACL	0xFA
#define CKY_INS_GET_BUILDID	0x70
#define CKY_INS_GET_RANDOM	0x72
#define CKY_INS_SEED_RANDOM	0x73
#define CKY_INS_NOP      	0x71

/* nonce validated only */
#define CKY_INS_LOGOUT   	0x61

/* nonce validated  & Secure Channel */
#define CKY_INS_IMPORT_KEY	0x32
#define CKY_INS_COMPUTE_CRYPT	0x36
#define CKY_INS_CREATE_PIN	0x40
#define CKY_INS_CHANGE_PIN	0x44
#define CKY_INS_CREATE_OBJ	0x5A
#define CKY_INS_DELETE_OBJ	0x52
#define CKY_INS_READ_OBJ 	0x56
#define CKY_INS_WRITE_OBJ	0x54

/* Secure channel only */
#define CKY_INS_INIT_UPDATE	0x50
#define CKY_INS_SEC_EXT_AUTH	0x82
#define CKY_INS_SEC_SET_LIFECYCLE	0xF0
#define CKY_INS_SEC_SET_PIN	0x04
#define CKY_INS_SEC_READ_IOBUF	0x08
#define CKY_INS_SEC_START_ENROLLMENT	0x0C

/* CAC */
#define CAC_INS_GET_CERTIFICATE 0x36
#define CAC_INS_SIGN_DECRYPT	0x42
#define CAC_INS_VERIFY_PIN	0x20
#define CAC_INS_GET_PROPERTIES	0x56
#define CAC_SIZE_GET_PROPERTIES	48

/*
 * Fixed return sized from various commands
 */
#define CKY_SIZE_GET_CPLCDATA	45
#define CKY_SIZE_LIST_KEYS	11
#define CKY_SIZE_LIST_PINS	2
#define CKY_SIZE_LIST_OBJECTS	14
#define CKY_SIZE_GET_STATUS	16
#define CKY_SIZE_GET_LIFE_CYCLE	1
#define CKY_SIZE_GET_LIFE_CYCLE_V2 4
#define CKY_SIZE_GET_BUILDID	4
#define CKY_SIZE_GET_ISSUER_INFO 0xe0
#define CKY_SIZE_GET_BUILTIN_ACL 7

/*
 * Crypt functions 
 */
/* functions */
#define CKY_CIPHER_INIT		1
#define CKY_CIPHER_PROCESS	2
#define CKY_CIPHER_FINAL		3
#define CKY_CIPHER_ONE_STEP	4  /* init and final in one APDU */

/* modes */
#define CKY_RSA_NO_PAD		0x00
#define CKY_RSA_PAD_PKCS1	0x01
#define CKY_DSA_SHA		0x10
#define CKY_DES_CBC_NOPAD	0x20
#define CKY_DES_ECB_NOPAD	0x21

/* operations (Cipher Direction) */
#define CKY_DIR_SIGN		0x01
#define CKY_DIR_VERIFY		0x02
#define CKY_DIR_ENCRYPT		0x03
#define CKY_DIR_DECRYPT		0x04

/* Data Location */
#define CKY_DL_APDU		0x01
#define CKY_DL_OBJECT		0x02

/* Key Types */
#define CKY_KEY_RSA_PUBLIC	0x01
#define CKY_KEY_RSA_PRIVATE	0x02
#define CKY_KEY_RSA_PRIVATE_CRT	0x03
#define CKY_KEY_DSA_PUBLIC		0x04
#define CKY_KEY_DSA_PRIVATE		0x05
#define CKY_KEY_DES		0x06
#define CKY_KEY_3DES		0x07
#define CKY_KEY_3DES3		0x08

/* List Operators */
#define CKY_LIST_RESET		0x00
#define CKY_LIST_NEXT		0x01

/* Max Size for a read block */
#define CKY_MAX_READ_CHUNK_SIZE	255
#define CKY_MAX_WRITE_CHUNK_SIZE	240

/* Life Cycle State */
#define CKY_APPLICATION_LOGICALLY_DELETED 0x00
#define CKY_APPLICATION_INSTALLED         0x03
#define CKY_APPLICATION_SELECTABLE        0x07
#define CKY_APPLICATION_PERSONALIZED      0x0f
#define CKY_APPLICATION_BLOCKED           0x7f
#define CKY_APPLICATION_LOCKED            0xff
#define CKY_CARDM_MANAGER_OP_READER       0x01
#define CKY_CARDM_MANAGER_INITIALIZED     0x03
#define CKY_CARDM_MANAGER_SECURED         0x0f
#define CKY_CARDM_MANAGER_LOCKED          0x7f
#define CKY_CARDM_MANAGER_TERMINATED      0xff

/*
 * The following factories 'Fill in' APDUs for each of the
 * functions described below. Nonces are not automatically added.
 * APDU's are for COOLKEY version 1.0 protocol. Callers should pass
 * in Already inited apdu's . Callers are responsible for freeing.
 * the APDU data, even in event of failure.
 */
CKY_BEGIN_PROTOS

/* function based factorys */
CKYStatus CKYAPDUFactory_SelectFile(CKYAPDU *apdu, const CKYBuffer *AID);
CKYStatus CKYAPDUFactory_SelectCardManager(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetCPLCData(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_ListKeys(CKYAPDU *apdu, CKYByte sequence);
CKYStatus CKYAPDUFactory_ComputeCryptInit(CKYAPDU *apdu, CKYByte keyNumber, 
			CKYByte mode, CKYByte direction, CKYByte location);
CKYStatus CKYAPDUFactory_ComputeCryptProcess(CKYAPDU *apdu, CKYByte keyNumber, 
				CKYByte location, const CKYBuffer *data);
CKYStatus CKYAPDUFactory_ComputeCryptFinal(CKYAPDU *apdu, CKYByte keyNumber, 
		CKYByte location, const CKYBuffer *data, const CKYBuffer *sig);
CKYStatus CKYAPDUFactory_ComputeCryptOneStep(CKYAPDU *apdu, CKYByte keyNumber, 
			    CKYByte mode, CKYByte direction, CKYByte location,
			    const CKYBuffer *data, const CKYBuffer *sig);
CKYStatus CKYAPDUFactory_CreatePIN(CKYAPDU *apdu, CKYByte pinNumber, 
				CKYByte maxAttempts, const char *pinValue);
CKYStatus CKYAPDUFactory_VerifyPIN(CKYAPDU *apdu, CKYByte pinNumber, 
						   const char *pinValue);
CKYStatus CKYAPDUFactory_ChangePIN(CKYAPDU *apdu, CKYByte pinNUmber, 
				const char *oldPin, const char *newPin);
CKYStatus CKYAPDUFactory_ListPINs(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_Logout(CKYAPDU *apdu, CKYByte pinNumber);

/* Future add WriteObject */
CKYStatus CKYAPDUFactory_CreateObject(CKYAPDU *apdu, unsigned long objectID,
 CKYSize size, unsigned short readACL, unsigned short writeACL, 
						unsigned short deleteACL);
CKYStatus CKYAPDUFactory_DeleteObject(CKYAPDU *apdu, unsigned long objectID, 
								CKYByte zero);
CKYStatus CKYAPDUFactory_ReadObject(CKYAPDU *apdu, unsigned long objectID, 
						CKYOffset offset, CKYByte size);
CKYStatus CKYAPDUFactory_ListObjects(CKYAPDU *apdu, CKYByte sequence);
CKYStatus CKYAPDUFactory_GetStatus(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_Noop(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetBuildID(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetLifeCycle(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetLifeCycleV2(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetRandom(CKYAPDU *apdu, CKYByte len);
CKYStatus CKYAPDUFactory_SeedRandom(CKYAPDU *apdu, const CKYBuffer *data);
CKYStatus CKYAPDUFactory_GetIssuerInfo(CKYAPDU *apdu);
CKYStatus CKYAPDUFactory_GetBuiltinACL(CKYAPDU *apdu);

CKYStatus CACAPDUFactory_SignDecrypt(CKYAPDU *apdu, const CKYBuffer *data);
CKYStatus CACAPDUFactory_VerifyPIN(CKYAPDU *apdu, const char *pin);
CKYStatus CACAPDUFactory_GetCertificate(CKYAPDU *apdu, CKYSize size);
CKYStatus CACAPDUFactory_GetProperties(CKYAPDU *apdu);

CKY_END_PROTOS

#endif /* CKY_FACTORY_H */
