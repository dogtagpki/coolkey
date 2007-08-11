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
* Copyright (C) 2006 Red Hat, Inc.
* All rights reserved.
* END COPYRIGHT BLOCK **/

/*****************************************************************
/
/ File   :   RegDll.cpp
/ Date   :   July 20, 2006
/ Purpose:   Register our Capi provider
/
******************************************************************/

#include "csp.h"
#include "windows.h"
#include "winreg.h"
#include "fcntl.h"
#include "io.h"

extern HINSTANCE g_hModule;


#define WINDOWS_CSP_PROVIDER \
	"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"
// Windows key values
#define TYPE_KEY		"Type"
#define IMAGE_KEY		"Image Path"
#define SIG_KEY			"Signature"

// CSP specific key values
#define LOG_KEY			"Logging"
#define KEYGEN_KEY		"KeyGenHack"
#define PIN_KEY			"PIN"
#define MODULE_KEY		"PKCS11Module"
#define DEFAULT_PKCS11_MODULE	"coolkeypk11.dll"
#define DEFAULT_PIN		"1234"


//
// set the key value if it doesn't exist
//
static LONG 
regSetValueIf(HKEY hKey, LPCTSTR lpSubKey, 
  		DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    DWORD size;
    LONG wrc = RegQueryValueEx(hKey,lpSubKey, 0, NULL, NULL, &size);
    if (wrc == ERROR_SUCCESS) {
	return wrc;
    }
    return RegSetValueEx(hKey, lpSubKey, 0, dwType, lpData, cbData);
}

static LONG
getThisLibraryName(char **returnedLibName, DWORD *returnedLibLen)
{
    char *cspLibraryName;
    DWORD cspLibraryLen;
    char myModuleName[MAX_PATH];

    *returnedLibName = NULL;
    *returnedLibLen = 0;

    cspLibraryLen = GetModuleFileName(g_hModule, 
				myModuleName, sizeof(myModuleName));
    if (cspLibraryLen == 0) {
	return GetLastError();
    }
    cspLibraryName = (char *)malloc(cspLibraryLen);
    if (cspLibraryName == NULL) {
	return ERROR_NOT_ENOUGH_MEMORY;
    }
    memcpy(cspLibraryName, myModuleName, cspLibraryLen);
    *returnedLibName = cspLibraryName;
    *returnedLibLen = cspLibraryLen;
    return ERROR_SUCCESS;
}

#define SIG_SUFFIX ".sig"

static char *
getSigFileName(const char *libName)
{
    int libLen = strlen(libName);
    char *sigFile = (char *)malloc(libLen+sizeof(SIG_SUFFIX));
    char *ext;

    if (sigFile == NULL) {
	return NULL;
    }

    ext = strrchr(libName, '.');
    if (ext) {
	libLen = ext - libName;
    }
    memcpy(sigFile,libName,libLen);
    memcpy(&sigFile[libLen],SIG_SUFFIX,sizeof(SIG_SUFFIX));
    return sigFile;
}

static DWORD
getFileSize(int fd)
{
   unsigned long offset;
   unsigned long current;

   current = lseek(fd, 0, SEEK_CUR);
   offset = lseek(fd, 0, SEEK_END);
   lseek(fd, current, SEEK_SET);
   return offset;
}

static LONG
getSignature(const char *cspLibrary, unsigned char **returnedSig, 
		DWORD *returnedSigLen)
{
    char *sigFile = getSigFileName(cspLibrary);
    int fd;
    unsigned char *signature = NULL;
    DWORD signatureLen;
    int error;
    LONG wrc = ERROR_SUCCESS;

    *returnedSig = NULL;
    *returnedSigLen = 0;

    if (sigFile == NULL) {
	return ERROR_NOT_ENOUGH_MEMORY;
    }

    fd = open (sigFile, O_RDONLY | O_BINARY);
    free(sigFile);
    if (fd < 0) {
	return GetLastError();
    }
    signatureLen = getFileSize(fd);

    signature = (unsigned char *)malloc(signatureLen);
    if (signature == NULL) {
	wrc = ERROR_NOT_ENOUGH_MEMORY;
	goto loser;
    }
    error = read(fd, signature, signatureLen);
    if (error != signatureLen) {
	wrc = (error < 0) ? GetLastError() : ERROR_FILE_NOT_FOUND;
	goto loser;
    }

    *returnedSig = signature;
    *returnedSigLen = signatureLen;
    
loser:
    close(fd);
    if (signature && (wrc != ERROR_SUCCESS) ) {
	free(signature);
    }
    return wrc;
}

	



STDAPI
DllUnregisterServer(void)
{
    HKEY provKey;
    DWORD disp;
    LONG wrc;

    wrc = RegCreateKeyEx(HKEY_LOCAL_MACHINE, WINDOWS_CSP_PROVIDER, 0, NULL,
			  REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, 
			  &provKey, &disp);
    if (wrc != ERROR_SUCCESS) {
	return HRESULT_FROM_WIN32(wrc);
    }
    RegDeleteKey(provKey, PROVIDER_NAME);
    RegCloseKey(provKey);
    return S_OK;
}


STDAPI
DllRegisterServer(void)
{
    HKEY provKey = NULL;
    HKEY cspKey = NULL;
    char *cspLibrary = NULL;
    unsigned char *signature = NULL;
    DWORD cspLibraryLen, signatureLen;
    DWORD dvalue;
    DWORD disp;
    LONG wrc;

    wrc = RegCreateKeyEx(HKEY_LOCAL_MACHINE, WINDOWS_CSP_PROVIDER, 0, NULL,
			  REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, 
			  &provKey, &disp);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = RegCreateKeyEx(provKey, PROVIDER_NAME, 0, NULL,
			  REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, 
			  &cspKey, &disp);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    dvalue = PROVIDER_TYPE;
    wrc = RegSetValueEx(cspKey, TYPE_KEY, 0, REG_DWORD, 
			(BYTE *)&dvalue, sizeof(dvalue));
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    dvalue = 0;
    wrc = regSetValueIf(cspKey, LOG_KEY, REG_DWORD, 
			(BYTE *)&dvalue, sizeof(dvalue));
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    dvalue = 1;
    wrc = regSetValueIf(cspKey, KEYGEN_KEY, REG_DWORD, 
			(BYTE *)&dvalue, sizeof(dvalue));
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = regSetValueIf(cspKey, PIN_KEY, REG_DWORD, 
			(BYTE *)DEFAULT_PIN, sizeof(DEFAULT_PIN));
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = regSetValueIf(cspKey, MODULE_KEY, REG_SZ, 
	(BYTE *)DEFAULT_PKCS11_MODULE, sizeof(DEFAULT_PKCS11_MODULE));
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = getThisLibraryName(&cspLibrary, &cspLibraryLen);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = RegSetValueEx(cspKey, IMAGE_KEY, 0, REG_SZ, 
			(BYTE *)cspLibrary, cspLibraryLen);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = getSignature(cspLibrary, &signature, &signatureLen);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
    wrc = RegSetValueEx(cspKey, SIG_KEY, 0, REG_BINARY, 
			signature, signatureLen);
    if (wrc != ERROR_SUCCESS) {
	goto loser;
    }
loser:
    if (signature) {
	free(signature);
    }
    if (cspLibrary) {
	free(cspLibrary);
    }
    if (cspKey) {
	RegCloseKey(cspKey);
	if (wrc != ERROR_SUCCESS) {
	    RegDeleteKey(provKey, PROVIDER_NAME);
	}
    }
    if (provKey) {
	RegCloseKey(provKey);
    }
    return HRESULT_FROM_WIN32(wrc);
}
