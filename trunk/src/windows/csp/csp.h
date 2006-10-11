/** BEGIN COPYRIGHT BLOCK
* This Program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; version 2 of the License.
*
* This Program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
* Place, Suite 330, Boston, MA 02111-1307 USA.
*
* Copyright (C) 2003-2004 Identity Alliance

* All rights reserved.
* END COPYRIGHT BLOCK **/

/*****************************************************************
/
/ File   :   csp.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_CSP_H__
#define __INCLUDE_CSP_H__

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#undef UNICODE

#ifndef CSP_PASSTHROUGH
#define PROVIDER_NAME "CoolKey PKCS #11 CSP"
#else
#define PROVIDER_NAME "CoolKey PKCS #11 CSP - Passthrough"
#endif

#define PROVIDER_TYPE PROV_RSA_FULL
#define PROVIDER_MAJOR_VERSION 1
#define PROVIDER_MINOR_VERSION 0

#define PP_REGISTER_CERTIFICATE     1000

// Logging macros
#define LOG flogf
#define BEGIN_API_CALL LOG("+%s() - called\n", __FUNCTION__)
#define END_API_CALL LOG(" -%s() - finished: %s (0x%X)\n", __FUNCTION__, rv ? "TRUE" : "FALSE", GetLastError());

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <set>
#include "cspdk.h"
#include "pkcs11.h"
#include "BinStr.h"
#include "Key.h"
#include "Session.h"
#include "State.h"

extern "C" HINSTANCE g_hModule;

namespace MCSP {

///////////////////////////////////////////////////////////////////////////////
// The global state
///////////////////////////////////////////////////////////////////////////////
extern State g_state;

///////////////////////////////////////////////////////////////////////////////
// Function prototypes (in alphabetical order)
///////////////////////////////////////////////////////////////////////////////
CK_ULONG ASN1Len(const CK_BYTE* buf, bool withHeader = true);
void DisplayError(const Session* context, const std::string& str);
void DisplayWin32Error(const Session* context);
bool DisplayPINDialog(BinStr* pin);
bool FindDefaultCert(Session* context, CK_OBJECT_HANDLE* phCert, BinStr* container);
bool FindLastContainer(Session* context, CK_OBJECT_HANDLE* phObj, BinStr* container);
bool FindObject(Session* context, CK_OBJECT_HANDLE* phObj, CK_OBJECT_CLASS objClass);
void flogf(const char* msg, ...);
bool GenUUID(BinStr* uuid);
bool GetExtKeyUsageFromCert(std::vector<std::string>* ext, const BinStr& cert);
bool GetModulusFromCert(Session* context, BinStr* modulus, BinStr* exponent, const BinStr& cert);
void HexIfBin(BinStr* str);
bool InitP11();
void Reverse(BinStr* buf);
void Reverse(LPBYTE buf, size_t len);
std::string StringifyAquireFlags(DWORD param);
std::string StringifyBin(const BinStr& data, bool hexMode = true);
std::string StringifyBin(const LPBYTE data, size_t len, bool hexMode = true);
std::string StringifyCALG(ALG_ID id);
std::string StringifyProvParam(DWORD param);
std::string GetCurrentExecutable();
std::string GetCurrentDLL();

// GetProvParam helpers
void GetProvParam_PP_ENUMALGS(Session* context, DWORD dwFlags,
                              OUT LPBYTE pbData,
                              IN OUT LPDWORD pcbDataLen);

void GetProvParam_PP_ENUMALGS_EX(Session* context, DWORD dwFlags,
                                 OUT LPBYTE pbData,
                                 IN OUT LPDWORD pcbDataLen);

void GetProvParam_PP_ENUMCONTAINERS(Session* context, DWORD dwFlags,
                                    OUT LPBYTE pbData,
                                    IN OUT LPDWORD pcbDataLen);

void PutDataIntoBuffer(LPBYTE dest, LPDWORD destLen, const LPBYTE source,
                       DWORD sourceLen);

} // namespace MCSP

#include "Error.h"

// END STANDARD CODE //////////////////////////////////////////////////////////
// END STANDARD CODE //////////////////////////////////////////////////////////
// END STANDARD CODE //////////////////////////////////////////////////////////
// END STANDARD CODE //////////////////////////////////////////////////////////
// END STANDARD CODE //////////////////////////////////////////////////////////

// Microsoft helper functions
namespace CryptoHelper {

BOOL CreatePrivateExponentOneKey(HCRYPTPROV hProv,
                                 DWORD dwKeySpec,
                                 HCRYPTKEY *hPrivateKey);

BOOL ExportPlainSessionBlob(HCRYPTKEY hPublicKey,
                            HCRYPTKEY hSessionKey,
                            LPBYTE *pbKeyMaterial,
                            DWORD *dwKeyMaterial);

BOOL ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial,
                            DWORD dwKeyMaterial,
                            HCRYPTKEY *hSessionKey);
} // namespace CryptoHelper

#endif // __INCLUDE_CSP_H__
