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
/ File   :   csp.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "csp.h"
#include "cspres.h" 

using namespace std;
using namespace MCSP;

// Globals
HINSTANCE g_hModule = NULL;
MCSP::State MCSP::g_state;

BOOL WINAPI
DllMain(
  HINSTANCE hinstDLL,  // handle to the DLL module
  DWORD fdwReason,     // reason for calling function
  LPVOID lpvReserved)  // reserved
{
   if (fdwReason == DLL_PROCESS_ATTACH)
   {
      LOG("Dllmain: DLL_PROCESS_ATTACH\n");
      DisableThreadLibraryCalls(hinstDLL);
      g_hModule = hinstDLL;
   }
   else if (fdwReason == DLL_PROCESS_DETACH)
   {
      LOG("Dllmain: DLL_PROCESS_DETACH\n");
      g_state.shutdown();
   }

   return TRUE;
}


/*
 -  CPAcquireContext
 -
 *  Purpose:
 *               The CPAcquireContext function is used to acquire a context
 *               handle to a cryptographic service provider (CSP).
 *
 *
 *  Parameters:
 *               OUT phProv         -  Handle to a CSP
 *               IN  szContainer    -  Pointer to a string which is the
 *                                     identity of the logged on user
 *               IN  dwFlags        -  Flags values
 *               IN  pVTable        -  Pointer to table of function pointers
 *
 *  Returns:
 */

BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable)
{
   BEGIN_API_CALL;
   LOG("Build: %s\n", "$Id$");
   LOG("Executable: \"%s\" (%s)\n", GetCurrentExecutable().c_str(), GetCurrentDLL().c_str());
   LOG("Container: \"%s\" Flags: %s (0x%X)\n", 
      szContainer, StringifyAquireFlags(dwFlags).c_str(), dwFlags);

   BOOL rv = TRUE;
   Session* context = 0;

#ifdef CSP_PASSTHROUGH
   rv = CryptAcquireContext(phProv, szContainer, MS_ENHANCED_PROV, PROV_RSA_FULL, dwFlags);
#else
   try
   {
      BinStr container_name, reader_name;
      Session::parseFQCN(szContainer, &container_name, &reader_name);

      // Missing output is only allowed for DELETEKEYSET
      if (!phProv && !(dwFlags & CRYPT_DELETEKEYSET))
         ThrowMsg(NTE_FAIL, "Can't return context, phProv is invalid");

      // Do one-time initialization of state
      if (g_state.init())
         LOG("CSP already initialized\n");
      else
      {
         LOG("Initializing CSP\n");

         // Initialize PKCS11
         if (!g_state.initP11(reader_name, dwFlags)) // LastError set by InitP11()
            ThrowMsg(0, "PKCS#11 initialization failed");

         g_state.init(true);
      }

      context = new Session;
      if (!context)
         Throw(NTE_NO_MEMORY);

      context->readerName_ = reader_name;

      if (dwFlags & CRYPT_SILENT)
         context->silent_ = true;
      if (dwFlags & CRYPT_VERIFYCONTEXT)
         context->verifyContext_ = true;
      if (dwFlags & CRYPT_MACHINE_KEYSET)
         context->machineKeyset_ = true;
      if (dwFlags & CRYPT_NEWKEYSET)
         context->newKeyset_ = true;

      // Set container name (either default or specified)
      if (strlen((char*)&container_name[0]) && !context->machineKeyset_)
      {
         if (context->verifyContext_)
            Throw(NTE_BAD_FLAGS);

         context->containerName_ = container_name;
         context->CKAID_ = context->containerName_;
         context->CKAID_.pop_back();
      }
      else if (!context->verifyContext_) // default container
      {
         CK_OBJECT_HANDLE hCert;
         BinStr ckaid;
         if (FindDefaultCert(context, &hCert, &ckaid) || FindLastContainer(context, &hCert, &ckaid))
         {
            LOG("Found default certificate or key-pair");
            context->CKAID_ = ckaid;
            context->containerName_ = ckaid;
            context->containerName_.BinToHex();
            context->containerName_.push_back(0);
         }
         else if (!strlen((char*)&container_name[0]))
         {
            LOG("Using UUID default container");
            context->containerName_ = context->cryptProvUUID_;
            context->containerName_.push_back(0);
            context->CKAID_ = context->cryptProvUUID_;
         }
      }

      context->CKAID_.HexToBin();

      if (context->containerName_.size()) {
         LOG("Container name: \"%s\"\n", &context->containerName_[0]);
      }

      if (context->CKAID_.size()) {
         LOG("CKA_ID: %s \"%s\"\n", StringifyBin(context->CKAID_).c_str(),
            StringifyBin(context->CKAID_, false).c_str());
      }

      if (!context->silent_ && !context->verifyContext_)
      {
         CK_SESSION_INFO info;
         if (g_state.p11->C_GetSessionInfo(context->p11_, &info) == CKR_OK && 
            ((info.state == CKS_RO_USER_FUNCTIONS) || (info.state == CKS_RW_USER_FUNCTIONS)))
         {
            LOG("PKCS#11 module in user mode, PIN verification skipped");
         }
         else
         {
#ifdef LOGIN_FOR_SESSION
            int pin_size;
            BinStr userPIN;
            userPIN.resize(256);
            if (!(pin_size = CSPDisplayPinDialog((char*)&userPIN[0], userPIN.size())))
               ThrowMsg(SCARD_W_CANCELLED_BY_USER, "PIN dialog cancelled");

            userPIN.resize(pin_size);

            CK_RV ck_rv = g_state.p11->C_Login(context->p11_, CKU_USER, 
                           (CK_UTF8CHAR*)&userPIN[0], (CK_ULONG)userPIN.size());

            if (ck_rv != CKR_OK)
            {
               DisplayError(context, "Error during PIN verification");
               Throw(NTE_FAIL);
            }
            else
               LOG("PIN Verification Successful\n");
#endif /* LOGIN_FOR_SESSION */
            g_state.login(context);
         }
      }

      if (!context->verifyContext_)
      {
         if (FindObject(context, 0, CKO_PRIVATE_KEY))
         {
            if (context->newKeyset_)
               ThrowMsg(NTE_EXISTS, "Container already exists and trying CRYPT_NEWKEYSET");
         }
         else if (!context->newKeyset_)
         {
            if (g_state.logging())
               DisplayError(context, "Could not find matching key-pair. This may just mean you are trying to use a certificate that does not have a matching key.\n\nIf you are attempting to install a certificate then it will not function properly. Your card may also be corrupt.");

            ThrowMsg(NTE_KEYSET_NOT_DEF, "Invalid container name and not CRYPT_NEWKEYSET");
         }
      }

      if (!(dwFlags & CRYPT_DELETEKEYSET))
      {
         g_state.addSession(context);
         *phProv = (HCRYPTPROV)context;
         LOG("New CSP session handle: 0x%X\n", context);
      }
      else
      {
         CK_ATTRIBUTE search = { CKA_ID, &context->CKAID_[0], context->CKAID_.size() };

         if (g_state.p11->C_FindObjectsInit(context->p11_, &search, 1) != CKR_OK)
            ThrowMsg(NTE_FAIL, "C_FindObjectsInit failed");

         vector<CK_OBJECT_HANDLE> deleted;
         CK_ULONG count;
         CK_OBJECT_HANDLE hObj;
         while (g_state.p11->C_FindObjects(context->p11_, &hObj, 1, &count) == CKR_OK && count > 0)
            deleted.push_back(hObj);

         // This attempts to delete everything we can, even if some things fail
         bool failed = false;
         vector<CK_OBJECT_HANDLE>::iterator itr = deleted.begin();
         for (; itr != deleted.end(); itr++)
         {
            if (g_state.p11->C_DestroyObject(context->p11_, *itr) != CKR_OK)
               failed = true;
         }

         if (failed)
            Throw(NTE_FAIL);

         delete context;
      }
   }
   catch(Error& e)
   {
      e.log();

      if (context)
         delete context;

      if (e.code_ != 0)
         SetLastError(e.code_);

      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -      CPReleaseContext
 -
 *      Purpose:
 *               The CPReleaseContext function is used to release a
 *               context created by CryptAcquireContext.
 *
 *     Parameters:
 *               IN  phProv        -  Handle to a CSP
 *               IN  dwFlags       -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPReleaseContext(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptReleaseContext(hProv, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      g_state.removeSession(context);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGenKey
 -
 *  Purpose:
 *                Generate cryptographic keys
 *
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      Algid   -  Algorithm identifier
 *               IN      dwFlags -  Flags values
 *               OUT     phKey   -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPGenKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

   Key* key = 0;

#ifdef CSP_PASSTHROUGH
   rv = CryptGenKey(hProv, Algid, dwFlags, phKey);
   key = (Key*)*phKey;
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);

      LOG("Algid:%s (0x%X) dwFlags:0x%X\n", StringifyCALG(Algid).c_str(), Algid, dwFlags);

      if (context->verifyContext_)
         Throw(NTE_PERM);

      if (dwFlags & CRYPT_USER_PROTECTED)
      {
         if (context->silent_)
            Throw(NTE_SILENT_CONTEXT);

         if (MessageBox(NULL, 
                        "An application is attempting to generate a keypair. Do you want to allow this?",
                        PROVIDER_NAME, 
                        MB_OKCANCEL | MB_ICONQUESTION | MB_TASKMODAL) == IDCANCEL)
         {
            Throw(NTE_FAIL);
         }
      }

      key = new Key;
      if (key == 0)
         Throw(NTE_NO_MEMORY);

      switch (Algid)
      {
      case CALG_DES:
      case CALG_3DES:
      case CALG_RC2:
         key->sessionKey_ = true;
         key->algId_ = Algid;
         if (!CryptGenKey(context->cryptProv_, Algid, dwFlags, &key->hFakeSessionKey_))
            ThrowMsg(0, "CryptGenKey failed");
         break;
      case CALG_RSA_SIGN:
      case CALG_RSA_KEYX:
      case AT_KEYEXCHANGE:
      case AT_SIGNATURE:
         {
            // FIXME: when doing on-card key operations, we may want to be able to
            //  export at least bulk keys.  We may want to store some sort of flag
            //  that allows us to export bulk keys, so this parameter may need to
            //  be handled at some point in the future
            
            // FIXME: EXPORTABLE check removed so the Wave test application will work (see README)
            //if (dwFlags & CRYPT_EXPORTABLE)
            //   ThrowMsg(NTE_BAD_FLAGS, "ERROR: Can't do CRYPT_EXPORTABLE");
            if (dwFlags & CRYPT_CREATE_SALT)
               ThrowMsg(NTE_BAD_FLAGS, "ERROR: Can't do CRYPT_CREATE_SALT");
            if (dwFlags & CRYPT_NO_SALT)
               ThrowMsg(NTE_BAD_FLAGS, "ERROR: Can't do CRYPT_NO_SALT");
            if (dwFlags & CRYPT_PREGEN)
               ThrowMsg(NTE_BAD_FLAGS, "ERROR: Can't do CRYPT_PREGEN");

            CK_OBJECT_HANDLE hPrivKey, hPubKey;
            key->sessionKey_ = false;

            if (Algid == AT_KEYEXCHANGE)
               key->algId_ = CALG_RSA_KEYX;
            else if (Algid == AT_SIGNATURE)
               key->algId_ = CALG_RSA_SIGN;
            else
               key->algId_ = Algid;

            if (FindObject(context, &hPrivKey, CKO_PRIVATE_KEY))
            {
               if (!FindObject(context, &hPubKey, CKO_PUBLIC_KEY))
               {
                  hPubKey = -1;
                  LOG("WARNING: Found private key but no matching public key (will attempt to use cert)\n");
               }

               key->hPrivateKey_ = hPrivKey;
               key->hPublicKey_ = hPubKey;
               LOG("KeyPair already on card; returning them as a \"new\" key pair\n");
            }
            else
            {
               CK_MECHANISM mechanism;
               mechanism.pParameter = NULL;
               mechanism.ulParameterLen = 0;
               mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

               CK_ULONG modulusBits = (dwFlags & 0xFFFF0000) >> 16;
               if (modulusBits == 0)
                  modulusBits = 1024;

               CK_BYTE publicExponent[3] = { 1, 0, 1};
               CK_BBOOL bTrue = TRUE;
               CK_ATTRIBUTE publicKeyTemplate[] = 
                  {
                     {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
                     {CKA_VERIFY, &bTrue, sizeof(bTrue)},
                     {CKA_TOKEN, &bTrue, sizeof(bTrue)},
                     //Setting the CKA_ID here won't work without P11 module changes
                     //{CKA_ID, &context->CKAID_[0], (CK_ULONG)context->CKAID_.size()},
                     {CKA_WRAP, &bTrue, sizeof(bTrue)},
                     {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
                     {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
                  };

               CK_ATTRIBUTE privateKeyTemplate[] = 
                  {
                     {CKA_TOKEN, &bTrue, sizeof(bTrue)},
                     {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
                     {CKA_TOKEN, &bTrue, sizeof(bTrue)},
                     //Setting the CKA_ID here won't work without P11 module changes
                     //{CKA_ID, &context->CKAID_[0], (CK_ULONG)context->CKAID_.size()},
                     {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
                     {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
                     {CKA_SIGN, &bTrue, sizeof(bTrue)},
                     {CKA_UNWRAP, &bTrue, sizeof(bTrue)}
                  };

               LOG("Modulus length: %d\n", modulusBits);

               if (!g_state.keyGenHack()) // Normal key generation mode
               {
                  CK_OBJECT_HANDLE hPubKey, hPrivKey;
                  CK_RV ck_rv;

                  ck_rv = g_state.p11->C_GenerateKeyPair(
                        context->p11_,
                        &mechanism,
                        publicKeyTemplate,
                        sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                        privateKeyTemplate,
                        sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                        &hPubKey,
                        &hPrivKey);

                  if (ck_rv != CKR_OK)
                  {
                     DisplayError(context, "Error generating key pair\n");
                     Throw(NTE_FAIL);
                  }

                  key->hPrivateKey_ = hPrivKey;
                  key->hPublicKey_ = hPubKey;

                  // Set the CKA_ID
                  CK_ATTRIBUTE pValueTemplate = 
                     { CKA_ID, &context->CKAID_[0], context->CKAID_.size() };

                  ck_rv = g_state.p11->C_SetAttributeValue(context->p11_, hPrivKey, &pValueTemplate, 1);
                  if (ck_rv != CKR_OK)
                     LOG("ERROR: Could not set the private key's CKA_ID\n");

                  ck_rv = g_state.p11->C_SetAttributeValue(context->p11_, hPubKey, &pValueTemplate, 1);
                  if (ck_rv != CKR_OK)
                     LOG("ERROR: Could not set the public key's CKA_ID\n");
               }
               else // Key generation hack (does key generation off-card, then imports)
               {
                  LOG("*********************** Using key generation hack ***********************\n");

                  HCRYPTKEY hKey;
                  if (!CryptGenKey(context->cryptProv_, Algid, CRYPT_EXPORTABLE, &hKey))
                     ThrowMsg(NTE_FAIL, "CryptGenKey failed");

                  DWORD dwKeyLen;
                  if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, 0, &dwKeyLen))
                     ThrowMsg(NTE_FAIL, "CryptExport key failed");

                  BinStr pbKey(dwKeyLen);
                  if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, &pbKey[0], &dwKeyLen))
                     ThrowMsg(NTE_FAIL, "CryptExport key failed");

                  if (key)
                  {
                     delete key;
                     key = 0;
                  }

                  // We import the new keys into _this_ CSP
                  rv = CPImportKey(hProv, &pbKey[0], dwKeyLen, 0, 0, (HCRYPTKEY*)&key);
               }
            }
         }
         break;
      default:
         ThrowMsg(NTE_BAD_ALGID, "Unsupported algorithm");
         break;
      }

      *phKey = (HCRYPTKEY)key;
      g_state.addKey(key);
   }
   catch(Error& e)
   {
      if (key)
         delete key;

      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   // Logging only
   {
      if (key->sessionKey_)
         LOG("Generated session key handle: 0x%X\n", key);
      else
         LOG("Generated key pair handle: 0x%X\n", key);

      LOG("algId:%s sessionKey:%s hPublicKey:0x%X hPrivateKey:0x%X hFakeKey:0x%X\n",
         StringifyCALG(key->algId_).c_str(), 
         key->sessionKey_ ? "true" : "false", 
         key->hPublicKey_, 
         key->hPrivateKey_,
         key->hFakeSessionKey_);
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPDeriveKey
 -
 *  Purpose:
 *                Derive cryptographic keys from base data
 *
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hBaseData -   Handle to base data
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPDeriveKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDeriveKey(hProv, Algid, hHash, dwFlags, phKey);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      rv = CryptDeriveKey(context->cryptProv_, Algid, hHash, dwFlags, phKey);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPDestroyKey
 -
 *  Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *
 *  Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDestroyKey(hKey);
#else
   try
   {
      g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
      {
         if (!CryptDestroyKey(key->hFakeSessionKey_))
         {
            LOG("CryptDestroyKey failed for key handle: 0x%X (MS default CSP handle: 0x%X)\n", 
               key, key->hFakeSessionKey_);
            Throw(0);
         }
      }

      g_state.removeKey(key);
      delete key;
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPSetKeyParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;
   LOG("hKey:0x%X dwParam:0x%X dwFlags:0x%X\n", hKey, dwParam, dwFlags);

#ifdef CSP_PASSTHROUGH
   rv = CryptSetKeyParam(hKey, dwParam, pbData, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);
   
      if (key->sessionKey_)
      {
         if (!CryptSetKeyParam(key->hFakeSessionKey_, dwParam, pbData, dwFlags))
            Throw(0);
      }
      else if (dwParam == KP_CERTIFICATE)
      {
         LOG("Adding certificate; CKA_ID: %s\n", StringifyBin(context->CKAID_).c_str());

         PCCERT_CONTEXT certContext =
            CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbData, ASN1Len(pbData));
         if (certContext == 0)
            ThrowMsg(NTE_FAIL, "CertCreateCertificateContext failed");

         BinStr modulus, exp, cert2;
         cert2.resize(ASN1Len(pbData));
         memcpy(&cert2[0], pbData, cert2.size());
         GetModulusFromCert(context, &modulus, &exp, cert2);

         DWORD labelSize =
            CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &certContext->pCertInfo->Subject,
               CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, 0, 0);
         BinStr label(labelSize);
         CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &certContext->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, (char*)&label[0], label.size());

         CertFreeCertificateContext(certContext);
         LOG("Certificate label is: \"%s\"\n", &label[0]);

         CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
         CK_BBOOL bTrue = TRUE;
         CK_CERTIFICATE_TYPE certType = CKC_X_509;

         CK_ATTRIBUTE atrTemplate[] = {
            { CKA_CLASS, &objClass, sizeof(objClass) },
            { CKA_VALUE, (CK_VOID_PTR)pbData, ASN1Len(pbData) },
            { CKA_TOKEN, &bTrue, sizeof(bTrue) },
            { CKA_ID, &context->CKAID_[0], context->CKAID_.size() },
            { CKA_LABEL, &label[0], label.size() - 1 },
            { CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) }
         };

         CK_OBJECT_HANDLE cert;

         if (FindObject(context, &cert, CKO_CERTIFICATE))
         {
            LOG("Warning: trying to overwrite existing certificate... ignoring request\n");

            // This won't work unless the token supports deleting objects and may crash
            //if (g_state.p11->C_SetAttributeValue(context->p11_, cert, &atrTemplate[0], atrTemplate.size()) != CKR_OK)
            //{
            //   ThrowMsg(NTE_FAIL, "C_SetAttributeValue failed");
            //}
         }
         else if (g_state.p11->C_CreateObject(context->p11_, atrTemplate, 
            sizeof(atrTemplate) / sizeof(CK_ATTRIBUTE), &cert) != CKR_OK)
         {
            ThrowMsg(NTE_FAIL, "Certificate creation failed\n");
         }
      }
      else
         ThrowMsg(NTE_BAD_TYPE, "Can't handle dwParam type");
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGetKeyParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;
   LOG("dwParam:0x%X dwFlags:0x%X\n", dwParam, dwFlags);

#ifdef CSP_PASSTHROUGH
   rv = CryptGetKeyParam(hKey, dwParam, pbData, pcbDataLen, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
         rv = CryptGetKeyParam(key->hFakeSessionKey_, dwParam, pbData, pcbDataLen, dwFlags);
      else if (dwParam == KP_CERTIFICATE)
      {
         CK_OBJECT_HANDLE hCert;
         if (!FindObject(context, &hCert, CKO_CERTIFICATE))
            ThrowMsg(NTE_FAIL, "Couldn't get certificate");

         CK_ATTRIBUTE pTemplate = { CKA_VALUE, 0, 0 };
         if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, &pTemplate, 1) != CKR_OK)
            ThrowMsg(NTE_FAIL, "C_GetAttributeValue failed");

         if (!pbData)
            *pcbDataLen = pTemplate.ulValueLen;
         else if (*pcbDataLen < pTemplate.ulValueLen)
            Throw(ERROR_MORE_DATA);
         else
         {
            *pcbDataLen = pTemplate.ulValueLen;
            pTemplate.pValue = pbData;
            if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, &pTemplate, 1) != CKR_OK)
               ThrowMsg(NTE_FAIL, "C_GetAttributeValue failed");
         }
      }
      else
         ThrowMsg(NTE_BAD_TYPE, "Can't handle dwParam type");
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   // Logging only
   {
      if (rv && pbData)
         LOG("Returning %u (0x%X) bytes data:\n%s\n\"%s\"\n", *pcbDataLen, *pcbDataLen,
            StringifyBin(pbData, *pcbDataLen).c_str(), 
            StringifyBin(pbData, *pcbDataLen, false).c_str());
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPSetProvParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;
   LOG("dwParam:0x%X dwFlags:0x%X\n", dwParam, dwFlags);

#ifdef CSP_PASSTHROUGH
   rv = CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);

      switch (dwParam)
      {
      case PP_ADMIN_PIN:
      case PP_KEYEXCHANGE_PIN:
      case PP_SIGNATURE_PIN:
         {
            CK_SESSION_INFO info;
            if (g_state.p11->C_GetSessionInfo(context->p11_, &info) == CKR_OK && 
               ((info.state == CKS_RO_USER_FUNCTIONS) || (info.state == CKS_RW_USER_FUNCTIONS)))
            {
               LOG("PKCS#11 module in user mode, PIN verification skipped");
            }
            else
            {
               CK_RV ck_rv = g_state.p11->C_Login(context->p11_, CKU_USER, 
                              (CK_UTF8CHAR*)pbData, (CK_ULONG)strlen((char*)pbData));

               if (ck_rv != CKR_OK)
                  ThrowMsg(NTE_FAIL, "Error during PIN verification");
               else
                  LOG("PIN Verification Successful: 0x%X\n", dwParam);
            }
         }
         break;
      case PP_REGISTER_CERTIFICATE:
         {
            if (context->verifyContext_)
               Throw(NTE_PERM);

            CK_OBJECT_HANDLE hCert;

            if (!pbData)
            {
               if (!FindObject(context, &hCert, CKO_CERTIFICATE))
               {
                  LOG("Could not find a certificate in container");
                  Throw(NTE_FAIL);
               }
            }
            else
            {
               Session temp(false);
               temp.p11_ = context->p11_;
               temp.containerName_ = (char*)pbData;
               temp.CKAID_ = (char*)pbData;
               temp.CKAID_.pop_back(); // remove null
               temp.CKAID_.HexToBin();
               if (!FindObject(&temp, &hCert, CKO_CERTIFICATE))
               {
                  LOG("Could not find a certificate in container: \"%s\"", &temp.containerName_[0]);
                  Throw(NTE_FAIL);
               }
            }

            CK_ATTRIBUTE attrib = { CKA_VALUE, 0, 0 };

            if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, &attrib, 1) != CKR_OK)
               Throw(NTE_FAIL);

            BinStr cert(attrib.ulValueLen);
            attrib.pValue = &cert[0];
            if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, &attrib, 1) != CKR_OK)
               Throw(NTE_FAIL);

            HCERTSTORE certStore = CertOpenSystemStore(hProv, "MY");
            if (certStore == 0)
               ThrowMsg(NTE_FAIL, "CertOpenSystemStore failed");

            PCCERT_CONTEXT certContext = 
               CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
                  &cert[0], cert.size());

            if (certContext == 0)
               ThrowMsg(NTE_FAIL, "CertCreateCertificateContext failed");

            PCCERT_CONTEXT newCert;
            if (!CertAddCertificateContextToStore(certStore, certContext, CERT_STORE_ADD_REPLACE_EXISTING, &newCert))
            {
               CertFreeCertificateContext(certContext);
               ThrowMsg(NTE_FAIL, "CertAddCertificateContextToStore failed");
            }

            BinStr containerName = (char*)pbData;
            CRYPT_KEY_PROV_INFO provInfo;
            provInfo.pwszContainerName = (LPWSTR) new unsigned short[containerName.size()];
            provInfo.pwszProvName = (LPWSTR) new unsigned short[strlen(PROVIDER_NAME) + 1];
            provInfo.dwProvType = PROVIDER_TYPE;
            provInfo.dwFlags = 0;
            provInfo.cProvParam = 0;
            provInfo.rgProvParam = 0;
            provInfo.dwKeySpec = AT_SIGNATURE;

            mbstowcs(provInfo.pwszContainerName, (char*)&containerName[0], containerName.size());
            mbstowcs(provInfo.pwszProvName, PROVIDER_NAME, strlen(PROVIDER_NAME) + 1);

            CertSetCertificateContextProperty(newCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &provInfo);

            delete [] provInfo.pwszContainerName;
            delete [] provInfo.pwszProvName;

            CertFreeCertificateContext(certContext);
            CertFreeCertificateContext(newCert);
            CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG);
         }
         break;
      default:
         ThrowMsg(NTE_BAD_TYPE, "Unknown parameter");
         break;
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGetProvParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN OUT  pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;
   LOG("dwParam = %s (%d), dwFlags = %d\n", 
      StringifyProvParam(dwParam).c_str(), dwParam, dwFlags);

#ifdef CSP_PASSTHROUGH
   if (dwParam == PP_NAME)
   {
      if (pbData)
         strcpy((char*)pbData, PROVIDER_NAME);
      *pcbDataLen = (DWORD)strlen(PROVIDER_NAME) + 1;
      rv = TRUE;
   }
   else if (dwParam == PP_KEYSET_SEC_DESCR)
   {
      rv = FALSE;
      SetLastError(NTE_BAD_TYPE);
   }
   else
      rv = CryptGetProvParam(hProv, dwParam, pbData, pcbDataLen, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);

      if ((dwFlags & CRYPT_FIRST) && (dwParam != PP_ENUMALGS)
            && (dwParam != PP_ENUMALGS) && (dwParam != PP_ENUMCONTAINERS)
            && (dwParam != PP_ENUMALGS_EX))
      {
         Throw(NTE_BAD_FLAGS);
      }

      switch (dwParam)
      {
      case PP_CONTAINER:
         if (context->verifyContext_)
            Throw(ERROR_INVALID_PARAMETER);

         PutDataIntoBuffer(pbData, pcbDataLen, &context->containerName_[0],
                           context->containerName_.size());
         break;
      case PP_ENUMALGS:
         GetProvParam_PP_ENUMALGS(context, dwFlags, pbData, pcbDataLen);
         break;
      case PP_ENUMALGS_EX:
         GetProvParam_PP_ENUMALGS_EX(context, dwFlags, pbData, pcbDataLen);
         break;
      case PP_ENUMCONTAINERS:
         GetProvParam_PP_ENUMCONTAINERS(context, dwFlags, pbData, pcbDataLen);
         break;
      case PP_IMPTYPE:
         {
            int type = CRYPT_IMPL_MIXED | CRYPT_IMPL_REMOVABLE;
            PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)&type, sizeof(type));
         }
         break;
      case PP_NAME:
         PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)PROVIDER_NAME, 
            (unsigned long)strlen(PROVIDER_NAME) + 1);
         break;
      case PP_VERSION:
         {
            DWORD version = PROVIDER_MAJOR_VERSION << 8 || PROVIDER_MINOR_VERSION;
            PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)&version, sizeof(version));
         }
         break;
      case PP_SIG_KEYSIZE_INC:
         {
            DWORD increment = 8;
            PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)&increment, sizeof(increment));
         }
         break;
      case PP_KEYX_KEYSIZE_INC:
         {
            DWORD increment = 8;
            PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)&increment, sizeof(increment));
         }
         break;
      case PP_UNIQUE_CONTAINER:
         PutDataIntoBuffer(pbData, pcbDataLen, &context->containerName_[0],
                           context->containerName_.size());
         break;
      case PP_PROVTYPE:
         {
            DWORD providerType = PROVIDER_TYPE;
            PutDataIntoBuffer(pbData, pcbDataLen, (LPBYTE)&providerType, sizeof(providerType));
         }
         break;
      case PP_KEYSET_SEC_DESCR:
      default:
         Throw(NTE_BAD_TYPE);
         break;
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   // Logging only
   {
      if (rv && pbData)
         LOG("Returning %u (0x%X) bytes data:\n%s\n\"%s\"\n", *pcbDataLen, *pcbDataLen,
            StringifyBin(pbData, *pcbDataLen).c_str(), 
            StringifyBin(pbData, *pcbDataLen, false).c_str());
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPSetHashParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
#else
   try
   {
      g_state.checkValidSession(hProv);
      rv = CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGetHashParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptGetHashParam(hHash, dwParam, pbData, pcbDataLen, dwFlags);
#else
   try
   {
      g_state.checkValidSession(hProv);
      rv = CryptGetHashParam(hHash, dwParam, pbData, pcbDataLen, dwFlags);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPExportKey
 -
 *  Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *  Parameters:
 *               IN  hProv         - Handle to the CSP user
 *               IN  hKey          - Handle to the key to export
 *               IN  hPubKey       - Handle to exchange public key value of
 *                                   the destination user
 *               IN  dwBlobType    - Type of key blob to be exported
 *               IN  dwFlags       - Flags values
 *               OUT pbData        -     Key blob data
 *               IN OUT pdwDataLen - Length of key blob in bytes
 *
 *  Returns:
 */

BOOL WINAPI
CPExportKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptExportKey(hKey, hPubKey, dwBlobType, dwFlags, pbData, pcbDataLen);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      LOG("hKey:0x%X hPubKey:0x%X dwBlobType:0x%X dwFlags:0x%X\n",
         hKey, hPubKey, dwBlobType, dwFlags);

      if (key->sessionKey_)
      {
         LOG("Trying to export hFakeSessionKey: 0x%X\n", key->hFakeSessionKey_);

         if (dwBlobType == PUBLICKEYBLOB)
            rv = CryptExportKey(key->hFakeSessionKey_, hPubKey, dwBlobType, dwFlags, pbData, pcbDataLen);
         else
         {
            DWORD publicKeyLen;
            g_state.checkValidKey(hPubKey);

            // Prevent infinite loop
            if (((Key*)hPubKey)->sessionKey_)
            {
               rv = CryptExportKey(
                  key->hFakeSessionKey_, 
                  ((Key*)hPubKey)->hFakeSessionKey_, 
                  dwBlobType, dwFlags, pbData, pcbDataLen);
            }
            else
            {
               if (!CPExportKey(hProv, hPubKey, 0, PUBLICKEYBLOB, 0, NULL, &publicKeyLen))
                  ThrowMsg(0, "CPExportKey failed");

               BinStr keyBlob(publicKeyLen);
		         if (!CPExportKey(hProv, hPubKey, 0, PUBLICKEYBLOB, 0, &keyBlob[0], &publicKeyLen)) 
                  ThrowMsg(0, "CPExportKey failed");

               HCRYPTKEY hPublicKey;
		         if (!CryptImportKey(context->cryptProv_, &keyBlob[0], publicKeyLen, 0, CRYPT_NO_SALT, &hPublicKey))
                  ThrowMsg(0, "CryptImportKey failed");

		         rv = CryptExportKey(key->hFakeSessionKey_, hPublicKey, dwBlobType, dwFlags, pbData, pcbDataLen);

		         CryptDestroyKey(hPubKey);
            }
         }
      } 
      else // non-session key
      {
         LOG("Signature/Exchange Key Looking for: %x\n", hKey);
         LOG("KeyAlg:%x  AlgRSA:%x\n", key->algId_, CALG_RSA_KEYX);

         switch (dwBlobType)
         {
         case SIMPLEBLOB:
            ThrowMsg(NTE_BAD_TYPE, "Unknown: SIMPLEBLOB\n");
            break;
         case PUBLICKEYBLOB:
            {
               CK_ATTRIBUTE atrTemplate[] = {
                  { CKA_MODULUS, 0, 0 },
                  { CKA_PUBLIC_EXPONENT, 0, 0 },
               };

               BinStr modulus, exponent;

               if (key->hPublicKey_ == -1) // No public key on card
               {
                  CK_OBJECT_HANDLE hObj;
                  if (!FindObject(context, &hObj, CKO_CERTIFICATE))
                     ThrowMsg(NTE_FAIL, "No public key and no certificate; bailing out");

                  CK_ATTRIBUTE attrib = { CKA_VALUE, 0, 0 };
                  if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &attrib, 1) != CKR_OK)
                     Throw(NTE_FAIL);

                  BinStr certData(attrib.ulValueLen);
                  attrib.pValue = &certData[0];
                  if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &attrib, 1) != CKR_OK)
                     Throw(NTE_FAIL);

                  if (!GetModulusFromCert(context, &modulus, &exponent, certData))
                     Throw(NTE_FAIL);
               }
               else
               {
                  CK_RV ck_rv = g_state.p11->C_GetAttributeValue(context->p11_, key->hPublicKey_, 
                     atrTemplate, sizeof(atrTemplate) / sizeof(CK_ATTRIBUTE));

                  if (ck_rv != CKR_OK)
                     ThrowMsg(NTE_FAIL, "Could not get the attribute values");

                  modulus.resize(atrTemplate[0].ulValueLen);
                  exponent.resize(atrTemplate[1].ulValueLen);
               }

               if (pbData == NULL)
               {
                  *pcbDataLen = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + modulus.size();
                  LOG("Length: %d\n", *pcbDataLen);
                  goto ExportKeyDone;
               }
               
               if (key->hPublicKey_ != -1)
               {
                  LOG("Modulus ulValueLen:%u  Exponent: %u\n", 
                     modulus.size(), exponent.size());

                  atrTemplate[0].pValue = &modulus[0];
                  atrTemplate[1].pValue = &exponent[0];

                  CK_RV ck_rv = g_state.p11->C_GetAttributeValue(context->p11_, key->hPublicKey_, 
                     atrTemplate, sizeof(atrTemplate) / sizeof(CK_ATTRIBUTE));

                  if (ck_rv != CKR_OK)
                     ThrowMsg(NTE_FAIL, "Could not read the attributes");
               }

               PUBLICKEYSTRUC header;

               // build the blob header
               header.bType = (BYTE)dwBlobType;
               header.bVersion = 2;
               header.reserved = 0;
               header.aiKeyAlg = CALG_RSA_KEYX;

               LPBYTE pos = pbData;
               // put the blob header into the char array
               memcpy(pos, &header, sizeof(header));
               pos += sizeof(header);

               // fill in the RSA structure
               RSAPUBKEY rsaPubKey;
               rsaPubKey.magic = 0x31415352;
               rsaPubKey.bitlen = atrTemplate[0].ulValueLen * 8; //bit length
               rsaPubKey.pubexp = 0;

               Reverse(&exponent);

               if (exponent.size() <= 4)
                  memcpy(&rsaPubKey.pubexp, &exponent[0], exponent.size());
               else
                  ThrowMsg(NTE_FAIL, "Can't handle exponent sizes more than 4");

               LOG("rsaPubKey.pubexp = 0x%X\n", rsaPubKey.pubexp);

               //put the rsaPubKey data in the BYTE array
               memcpy(pos, &rsaPubKey, sizeof(rsaPubKey));
               pos += sizeof(rsaPubKey);

               LOG("Public exponent: %02x %02x %02x %02x\n",
                     pbData[16], pbData[17], pbData[18], pbData[19]);

               memcpy(pos, &modulus[0], modulus.size());
               Reverse(pos, modulus.size());
               pos += modulus.size();
            }
            break;
         case PRIVATEKEYBLOB:
            ThrowMsg(NTE_BAD_TYPE, "Unknown: PRIVATEKEYBLOB\n");
            break;
         case OPAQUEKEYBLOB:
            ThrowMsg(NTE_BAD_TYPE, "Unknown: OPAQUEKEYBLOB\n");
            break;
         }
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

ExportKeyDone:
   // Logging only
   {
      if (rv && pbData)
         LOG("Returning %u (0x%X) bytes data:\n%s\n\"%s\"\n", *pcbDataLen, *pcbDataLen,
            StringifyBin(pbData, *pcbDataLen).c_str(), 
            StringifyBin(pbData, *pcbDataLen, false).c_str());
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPImportKey
 -
 *  Purpose:
 *                Import cryptographic keys
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *  Returns:
 */

BOOL WINAPI
CPImportKey(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptImportKey(hProv, pbData, cbDataLen, hPubKey, dwFlags, phKey);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key* pubKey = reinterpret_cast<Key*>(hPubKey);

      BLOBHEADER* header = (BLOBHEADER*)pbData;

      switch(header->bType)
      {
      case SIMPLEBLOB:
         // What a terrible name, this is the most complicated of blob types
         LOG("Trying to import SIMPLEBLOB\n");
         {
            ALG_ID id = *((ALG_ID*)&pbData[sizeof(BLOBHEADER)]);
            DWORD headerSize = sizeof(BLOBHEADER) + sizeof(ALG_ID);
            BinStr data(cbDataLen - headerSize);
            memcpy(&data[0], &pbData[headerSize], data.size());
            
            CK_OBJECT_HANDLE hPrivKey;
            if (!FindObject(context, &hPrivKey, CKO_PRIVATE_KEY))
               ThrowMsg(NTE_FAIL, "Could not find private key");

            CK_MECHANISM mechanism;
            mechanism.mechanism = CKM_RSA_PKCS;
            mechanism.pParameter = NULL;
            mechanism.ulParameterLen = 0;
            CK_RV ck_rv = g_state.p11->C_DecryptInit(context->p11_, &mechanism, hPrivKey);
            if (ck_rv != CKR_OK)
               ThrowMsg(NTE_FAIL, "C_DecryptInit failed");

            Reverse(&data);

            BinStr decrypted(data.size());
            CK_ULONG decrypt_size = static_cast<CK_ULONG>(decrypted.size());
            ck_rv = g_state.p11->C_Decrypt(context->p11_, &data[0], (CK_ULONG)data.size(), &decrypted[0], &decrypt_size);
            if (ck_rv != CKR_OK)
               ThrowMsg(NTE_FAIL, "C_Decrypt failed");

            decrypted.resize(decrypt_size);
            Reverse(&decrypted);

            LOG("Session key is (LEN:%u ALG:%s): %s\n", 
               decrypted.size(), StringifyCALG(header->aiKeyAlg).c_str(), StringifyBin(decrypted).c_str());

            HCRYPTKEY hPubPrivKey;
            if (!CryptoHelper::CreatePrivateExponentOneKey(
               context->cryptProv_, AT_KEYEXCHANGE, &hPubPrivKey))
            {
               ThrowMsg(NTE_FAIL, "CryptoHelper::CreatePrivateExponentOneKey failed");
            }

            // We reverse it again here because ImportPlainSessionBlob will reverse
            // it once more (!) FIXME: please
            Reverse(&decrypted);

            HCRYPTKEY hKey;
            if (!CryptoHelper::ImportPlainSessionBlob(context->cryptProv_, hPubPrivKey, 
               header->aiKeyAlg, &decrypted[0], decrypted.size(), &hKey))
            {
               ThrowMsg(NTE_FAIL, "CryptoHelper::ImportPlainSessionBlob failed");
            }

            CryptDestroyKey(hPubPrivKey);

            Key* newKey = new Key(true);
            if (!newKey)
               Throw(NTE_NO_MEMORY);

            newKey->algId_ = header->aiKeyAlg;
            newKey->hFakeSessionKey_ = hKey;

            *phKey = reinterpret_cast<HCRYPTKEY>(newKey);
            g_state.addKey(newKey);
         }
         break;
      case PUBLICKEYBLOB:
         // FIXME: import to P11 module not CryptoAPI?
         LOG("Trying to import PUBLICKEYBLOB\n");
         {
            Key* key = new Key(true);
            if (!key)
               Throw(NTE_NO_MEMORY);

            key->algId_ = header->aiKeyAlg;
            if (!CryptImportKey(context->cryptProv_, pbData, cbDataLen, 
               hPubKey, dwFlags, &key->hFakeSessionKey_))
            {
               delete key;
               Throw(NTE_FAIL);
            }

            *phKey = (HCRYPTKEY)key;
            g_state.addKey(key);
         }
         break;
      case PRIVATEKEYBLOB:
         LOG("Trying to import PRIVATEKEYBLOB\n");
         {
            BinStr data(cbDataLen);
            memcpy(&data[0], pbData, cbDataLen);

            BLOBHEADER* header = (BLOBHEADER*)&data[0];
            RSAPUBKEY* rsakey = (RSAPUBKEY*)&data[sizeof(BLOBHEADER)];
            BYTE* pos = &data[0] + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
            
            CK_ULONG bitLen8 = rsakey->bitlen / 8;
            CK_ULONG bitLen16 = rsakey->bitlen / 16;

            BYTE* modulus = pos;
            pos += bitLen8;
            BYTE* prime1 = pos;
            pos += bitLen16;
            BYTE* prime2 = pos;
            pos += bitLen16;
            BYTE* exponent1 = pos;
            pos += bitLen16;
            BYTE* exponent2 = pos;
            pos += bitLen16;
            BYTE* coefficient = pos;
            pos += bitLen16;
            BYTE* privateExponent = pos;
            pos += bitLen8;

            BinStr pubExp(4);
            memcpy(&pubExp[0], &rsakey->pubexp, sizeof(rsakey->pubexp));

            // Shrink the exponent
            while (pubExp.size() > 1 && pubExp[pubExp.size()-1] == 0x00)
               pubExp.pop_back();

            Reverse(&pubExp);
            Reverse(modulus, bitLen8);
            Reverse(prime1, bitLen16);
            Reverse(prime2, bitLen16);
            Reverse(exponent1, bitLen16);
            Reverse(exponent2, bitLen16);
            Reverse(coefficient, bitLen16);
            Reverse(privateExponent, bitLen8);

            CK_ULONG cls = 0x03;
            CK_ULONG keyType = 0x00;
            CK_BYTE bTrue = 0x01;
            CK_ATTRIBUTE pTemplate[] = {
               { CKA_CLASS, &cls, sizeof(cls) },
               { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
               { CKA_TOKEN, &bTrue, sizeof(bTrue) },
               { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
               { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
               { CKA_ID, &context->containerName_[0], (CK_ULONG)context->containerName_.size() - 1 },
               { CKA_MODULUS, modulus, bitLen8 },
               { CKA_PRIVATE_EXPONENT, privateExponent, bitLen8 },
               { CKA_PUBLIC_EXPONENT, &pubExp[0], (CK_ULONG)pubExp.size() },
               { CKA_PRIME_1, prime1, bitLen16 },
               { CKA_PRIME_2, prime2, bitLen16 },
               { CKA_EXPONENT_1, exponent1, bitLen16 },
               { CKA_EXPONENT_2, exponent2, bitLen16 },
               { CKA_COEFFICIENT, coefficient, bitLen16 } };

            CK_OBJECT_HANDLE hPrivKey, hPubKey;
            CK_RV ck_rv;
            ck_rv = g_state.p11->C_CreateObject(context->p11_, &pTemplate[0], 
               sizeof(pTemplate) / sizeof(CK_ATTRIBUTE), &hPrivKey);
            if (ck_rv != CKR_OK)
               ThrowMsg(NTE_FAIL, "C_CreateObject failed");

            if (!FindObject(context, &hPubKey, CKO_PUBLIC_KEY))
               ThrowMsg(NTE_FAIL, "Could not find public key");

            Key* key = new Key(false);
            if (!key)
               Throw(NTE_NO_MEMORY);

            key->hPrivateKey_ = hPrivKey;
            key->hPublicKey_ = hPubKey;

            *phKey = (HCRYPTKEY)key;
            g_state.addKey(key);
         }
         break;
      case PLAINTEXTKEYBLOB:
         LOG("Trying to import PLAINTEXTKEYBLOB\n");
         Throw(NTE_BAD_TYPE);
         break;
      case OPAQUEKEYBLOB:
         LOG("Trying to import OPAQUEKEYBLOB\n");
         Throw(NTE_BAD_TYPE);
         break;
      case PUBLICKEYBLOBEX:
         LOG("Trying to import PUBLICKEYBLOBEX\n");
         Throw(NTE_BAD_TYPE);
         break;
      case SYMMETRICWRAPKEYBLOB:
         LOG("Trying to import SYMMETRICWRAPKEYBLOB\n");
         Throw(NTE_BAD_TYPE);
         break;
      default:
         LOG("Trying to import UNKNOWN blob type\n");
         Throw(NTE_BAD_TYPE);
         break;
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPEncrypt
 -
 *  Purpose:
 *                Encrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *  Returns:
 */

BOOL WINAPI
CPEncrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptEncrypt(hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen, cbBufLen);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
      {
         LOG("Input data: %s\n", StringifyBin(pbData, *pcbDataLen).c_str());
         LOG("Input data: %s\n", StringifyBin(pbData, *pcbDataLen, false).c_str());
         rv = CryptEncrypt(key->hFakeSessionKey_, hHash, fFinal, dwFlags, pbData, pcbDataLen, cbBufLen);
         LOG("Outut data: %s\n", StringifyBin(pbData, *pcbDataLen).c_str());
         LOG("Outut data: %s\n", StringifyBin(pbData, *pcbDataLen, false).c_str());
      }
      else
      {
          // FIXME: Encrypt at PKCS#11 module
         Throw(NTE_BAD_ALGID);
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPDecrypt
 -
 *  Purpose:
 *                Decrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *  Returns:
 */

BOOL WINAPI
CPDecrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDecrypt(hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
      {
         LOG("Decrypting with default MS provider\n");
         LOG("Input data: %s\n", StringifyBin(pbData, *pcbDataLen, false).c_str());
         rv = CryptDecrypt(key->hFakeSessionKey_, hHash, fFinal, dwFlags, pbData, pcbDataLen);
         LOG("Outut data: %s\n", StringifyBin(pbData, *pcbDataLen, false).c_str());
      }
      else
      {
         LOG("Decrypting with PKCS#11\n");
         CK_MECHANISM decryptMechanism;
         decryptMechanism.mechanism = CKM_RSA_PKCS;
         decryptMechanism.pParameter = 0;
         decryptMechanism.ulParameterLen = 0;

         CK_RV ck_rv = g_state.p11->C_DecryptInit(context->p11_, &decryptMechanism, key->hPrivateKey_);
         if (ck_rv == CKR_OK)
         {
            LOG("Datalen: %d\n", *pcbDataLen);
            Reverse(pbData, *pcbDataLen);
            LOG("Data Reversed: %s\n", StringifyBin(pbData, *pcbDataLen).c_str());

            BinStr cleartext;
            cleartext.resize(128);
            DWORD cleartextLen = cleartext.size();

            ck_rv = g_state.p11->C_Decrypt(context->p11_, pbData, *pcbDataLen, &cleartext[0], &cleartextLen);
            if (ck_rv != CKR_OK)
            {
               LOG("Could not perform the decryption, ck_rv: %x\n", ck_rv);
               Throw(NTE_FAIL);
            }

            memcpy(pbData, &cleartext[0], cleartext.size());

            *pcbDataLen = cleartextLen;
         }
         else
            ThrowMsg(NTE_FAIL, "Could not initialize the decryption");
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPCreateHash
 -
 *  Purpose:
 *                initate the hashing of a stream of data
 *
 *
 *  Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey   -   Optional handle to a key
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPCreateHash(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      // FIXME: Keyed hash algorithms can not be handled because this assumes
      //        hKey is valid even though it's probably not a default crypto
      //        provider key
      rv = CryptCreateHash(context->cryptProv_, Algid, hKey, dwFlags, phHash);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPHashData
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptHashData(hHash, pbData, cbDataLen, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      rv = CryptHashData(hHash, pbData, cbDataLen, dwFlags);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   // Logging only
   {
      if (pbData)
         LOG("Hashing %u (0x%X) bytes data:\n%s\n\"%s\"\n", cbDataLen, cbDataLen,
            StringifyBin((LPBYTE)pbData, cbDataLen).c_str(), 
            StringifyBin((LPBYTE)pbData, cbDataLen, false).c_str());
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPHashSessionKey
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */

BOOL WINAPI
CPHashSessionKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptHashSessionKey(hHash, hKey, dwFlags);
#else
   try
   {
      g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
         rv = CryptHashSessionKey(hHash, key->hFakeSessionKey_, dwFlags);
      else
         ThrowMsg(NTE_FAIL, "ERROR: Non-session key");
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPSignHash
 -
 *  Purpose:
 *                Create a digital signature from a hash
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  dwKeySpec    -  Key pair to that is used to sign with
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignature  -  Pointer to signature data
 *               IN OUT dwHashLen -  Pointer to the len of the signature data
 *
 *  Returns:
 */

BOOL WINAPI
CPSignHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptSignHash(hHash, dwKeySpec, 0, dwFlags, pbSignature, pcbSigLen);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);

      // Find the key we want to sign with
      CK_OBJECT_HANDLE hPrivKey;
      if (!FindObject(context, &hPrivKey, CKO_PRIVATE_KEY))
      {
         LOG("Could not find key; container is: %s\n", &context->containerName_[0]);
         Throw(NTE_NO_KEY);
      }

      DWORD dwHashLen;
      if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashLen, 0))
      {
         DisplayError(context, "Could not get length using getHashParam\n");
         Throw(NTE_BAD_HASH);
      }

      LOG("Hash len: %d\n", dwHashLen);
      BinStr pbHash(dwHashLen);

      // Get the hash itself
      if (!CryptGetHashParam(hHash, HP_HASHVAL, &pbHash[0], &dwHashLen, 0))
      {
         DisplayError(context, "Error during reading hash value.");
         Throw(NTE_BAD_HASH);
      }

      DWORD hashAlg;
      DWORD hashAlgSize = sizeof(hashAlg);
      if (!CryptGetHashParam(hHash, HP_ALGID, (BYTE*)&hashAlg, &hashAlgSize, 0))
      {
         DisplayError(context, "Error during reading hash ALGID value.");
         Throw(NTE_BAD_HASH);
      }

      if (!(dwFlags & CRYPT_NOHASHOID))
      {
         // Add PKCS#7 header
         BinStr temp;
         if (hashAlg == CALG_MD5)
         {
            LOG("CALG_MD5 hash\n");
            BYTE pkcs7[] = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 
                              0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 
                              0x04, 0x10 };
            temp.resize(sizeof(pkcs7) + pbHash.size());
            memcpy(&temp[0], pkcs7, sizeof(pkcs7));
            memcpy(&temp[sizeof(pkcs7)], &pbHash[0], pbHash.size());
            pbHash.swap(temp);
         }
         else if (hashAlg == CALG_SHA1)
         {
            LOG("CALG_SHA1 hash\n");
            BYTE pkcs7[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 
                              0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
            temp.resize(sizeof(pkcs7) + pbHash.size());
            memcpy(&temp[0], pkcs7, sizeof(pkcs7));
            memcpy(&temp[sizeof(pkcs7)], &pbHash[0], pbHash.size());
            pbHash.swap(temp);
         }
         else if (hashAlg == CALG_SSL3_SHAMD5)
         {
            // Intentionally blank; should not need to do anything else
         }
         else
         {
            LOG("Unsupported hash type: 0x%X\n", hashAlg);
            Throw(NTE_BAD_HASH);
         }
      }

      if (pbSignature == NULL)
      {
         CK_ATTRIBUTE privKeyMod = { CKA_MODULUS, 0, 0 };

         if (g_state.p11->C_GetAttributeValue(context->p11_, hPrivKey, &privKeyMod, 1) != CKR_OK || privKeyMod.ulValueLen == 0)
         {
            LOG("C_GetAttributeValue failed; using (slow) C_Sign to get signature length\n");

            CK_MECHANISM signingMechanism;
            signingMechanism.mechanism = CKM_RSA_PKCS;
            signingMechanism.pParameter = NULL;
            signingMechanism.ulParameterLen = 0;

            CK_RV ck_rv = g_state.p11->C_SignInit(context->p11_, &signingMechanism, hPrivKey);
            if (ck_rv != CKR_OK)
            {
               LOG("Error during SignInit, errorcode 0x%X\n", ck_rv);
               Throw(NTE_FAIL);
            }

            ck_rv = g_state.p11->C_Sign(context->p11_, &pbHash[0], pbHash.size(), 0, &privKeyMod.ulValueLen);
            if (ck_rv != CKR_OK)
            {
               LOG("Error during C_Sign to get signature length %x\n", ck_rv);
               Throw(NTE_FAIL);
            }

            // We now must actually do the C_Sign to finalize the session
            BinStr temp_buf(privKeyMod.ulValueLen);
            ck_rv = g_state.p11->C_Sign(context->p11_, &pbHash[0], pbHash.size(), &temp_buf[0], &privKeyMod.ulValueLen);
            if (ck_rv != CKR_OK)
            {
               LOG("Error during C_Sign %x\n", ck_rv);
               Throw(NTE_FAIL);
            }
         }

         *pcbSigLen = privKeyMod.ulValueLen;
      }
      else
      {
         CK_MECHANISM signingMechanism;
         signingMechanism.mechanism = CKM_RSA_PKCS;
         signingMechanism.pParameter = NULL;
         signingMechanism.ulParameterLen = 0;

         CK_RV ck_rv = g_state.p11->C_SignInit(context->p11_, &signingMechanism, hPrivKey);
         if (ck_rv != CKR_OK)
         {
            LOG("Error during SignInit, errorcode 0x%Xcd \n", ck_rv);
            Throw(NTE_FAIL);
         }

         LOG("Buffer size: %d\t\n", *pcbSigLen);
         LOG("C_Sign called with data: %s\n", StringifyBin(pbHash, true).c_str());
         ck_rv = g_state.p11->C_Sign(context->p11_, &pbHash[0], pbHash.size(), pbSignature, pcbSigLen);
         if (ck_rv == CKR_BUFFER_TOO_SMALL)
         {
            // We need to do this to close the sign session.  There is no other way :(
            LOG("Buffer too small, calling C_Sign to finalize session\n");
            BinStr temp_buf(*pcbSigLen);
            g_state.p11->C_Sign(context->p11_, &pbHash[0], pbHash.size(), &temp_buf[0], pcbSigLen);
            Throw(ERROR_MORE_DATA);
         }
         else if (ck_rv != CKR_OK)
         {
            LOG("Error during Sign %x\n", ck_rv);
            Throw(NTE_FAIL);
         }

         LOG("The signature is (len %d): %s\n", 
            *pcbSigLen, StringifyBin(pbSignature, *pcbSigLen).c_str());

         Reverse(pbSignature, *pcbSigLen);
      }
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   // Logging only
   if (rv)
   {
      DWORD dwHashLen = 1024;
      BinStr pbHash(dwHashLen);
      if (CryptGetHashParam(hHash, HP_HASHVAL, &pbHash[0], &dwHashLen, 0))
      {
         pbHash.resize(dwHashLen);
         LOG("The hash is: %s\n", StringifyBin(pbHash).c_str());
         Reverse(&pbHash);
         LOG("The hash is (reversed): %s\n", StringifyBin(pbHash).c_str());
      }

      if (pbSignature)
         LOG("Returning %u (0x%X) bytes data:\n%s\n\"%s\"\n", *pcbSigLen, *pcbSigLen,
            StringifyBin(pbSignature, *pcbSigLen).c_str(), 
            StringifyBin(pbSignature, *pcbSigLen, false).c_str());
   }

   END_API_CALL;
   return rv;
}


/*
 -  CPDestroyHash
 -
 *  Purpose:
 *                Destroy the hash object
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDestroyHash(hHash);
#else
   try
   {
      g_state.checkValidSession(hProv);
      rv = CryptDestroyHash(hHash);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPVerifySignature
 -
 *  Purpose:
 *                Used to verify a signature against a hash object
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  sDescription -  String describing the signed data
 *               IN  dwFlags      -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptVerifySignature(hHash, pbSignature, cbSigLen, hPubKey, 0, dwFlags);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);

      LOG("Must first import the public key to the default CSP\n");
      DWORD publicKeyLen;
      if (CPExportKey(
               hProv,
               hPubKey,
               0,
               PUBLICKEYBLOB,
               0,
               NULL,
               &publicKeyLen))
      {
         LOG("Got Key length successfully, %d\n", publicKeyLen);
      }
      else
         ThrowMsg(0, "Could not get keylength");

      BinStr keyBlob;
      keyBlob.resize(publicKeyLen);

      if (CPExportKey(
               hProv,
               hPubKey,
               0,
               PUBLICKEYBLOB,
               0,
               &keyBlob[0],
               &publicKeyLen))
      {
         LOG("Got the public key successfully\n");
      }
      else
         ThrowMsg(0, "Could not get public key");

      LOG("The key blob data is (len %d): %s\n", 
         keyBlob.size(), StringifyBin(keyBlob).c_str());

      HCRYPTKEY hKey;
      if (CryptImportKey(
               context->cryptProv_,
               &keyBlob[0],
               keyBlob.size(),
               0,
               CRYPT_NO_SALT,
               &hKey))
      {
         LOG("Imported key to CSP successfully\n");
      }
      else
         ThrowMsg(0, "Could not import the key to the CSP");

      rv = CryptVerifySignature(hHash, pbSignature, cbSigLen, hKey, NULL, dwFlags);

      CryptDestroyKey(hKey);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGenRandom
 -
 *  Purpose:
 *                Used to fill a buffer with random bytes
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the user identifcation
 *               IN  dwLen         -  Number of bytes of random data requested
 *               IN OUT pbBuffer   -  Pointer to the buffer where the random
 *                                    bytes are to be placed
 *
 *  Returns:
 */

BOOL WINAPI
CPGenRandom(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptGenRandom(hProv, cbLen, pbBuffer);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      if (g_state.p11->C_GenerateRandom(context->p11_, pbBuffer, cbLen) != CKR_OK)
         ThrowMsg(NTE_FAIL, "C_GenerateRandom failed");
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPGetUserKey
 -
 *  Purpose:
 *                Gets a handle to a permanent user key
 *
 *
 *  Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *  Returns:
 */

BOOL WINAPI
CPGetUserKey(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey)
{
   BOOL rv = TRUE;
   BEGIN_API_CALL;

   LOG("dwKeySpec: 0x%X\n", dwKeySpec);

#ifdef CSP_PASSTHROUGH
   rv = CryptGetUserKey(hProv, dwKeySpec, phUserKey);
#else
   try
   {
      Session::Ptr context = g_state.checkValidSession(hProv);
      if (phUserKey == 0)
         Throw(NTE_BAD_KEY);

      ALG_ID newAlgId = dwKeySpec;

      if (newAlgId == AT_KEYEXCHANGE)
         newAlgId = CALG_RSA_KEYX;
      else if (newAlgId == AT_SIGNATURE)
         newAlgId = CALG_RSA_SIGN;

      CK_OBJECT_HANDLE hPubKey, hPrivKey;

      // Find the objects we want
      if (!FindObject(context, &hPrivKey, CKO_PRIVATE_KEY))
         ThrowMsg(NTE_NO_KEY, "ERROR: Could not find the private key");
      if (!FindObject(context, &hPubKey, CKO_PUBLIC_KEY))
      {
         hPubKey = -1;
         LOG("WARNING: Could not find the public key (will attempt to get it from cert when needed)\n");
      }

      Key* keyPair = new Key(false);
      if (!keyPair)
         Throw(NTE_NO_MEMORY);

      keyPair->algId_ = newAlgId;
      keyPair->hPrivateKey_ = hPrivKey;
      keyPair->hPublicKey_ = hPubKey;

      *phUserKey = (HCRYPTKEY)keyPair;
      g_state.addKey(keyPair);

      LOG("GetUserKey returns %x\n", *phUserKey);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPDuplicateHash
 -
 *  Purpose:
 *                Duplicates the state of a hash and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hHash          -  Handle to a hash
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phHash         -  Handle to the new hash
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDuplicateHash(hHash, pdwReserved, dwFlags, phHash);
#else
   try
   {
      g_state.checkValidSession(hProv);
      rv = CryptDuplicateHash(hHash, pdwReserved, dwFlags, phHash);
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}


/*
 -  CPDuplicateKey
 -
 *  Purpose:
 *                Duplicates the state of a key and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hKey           -  Handle to a key
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phKey          -  Handle to the new key
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
   BOOL rv = FALSE;
   BEGIN_API_CALL;

#ifdef CSP_PASSTHROUGH
   rv = CryptDuplicateKey(hKey, pdwReserved, dwFlags, phKey);
#else
   try
   {
      g_state.checkValidSession(hProv);
      Key::Ptr key = g_state.checkValidKey(hKey);

      if (key->sessionKey_)
         rv = CryptDuplicateKey(key->hFakeSessionKey_, pdwReserved, dwFlags, phKey);
      else
         ThrowMsg(ERROR_CALL_NOT_IMPLEMENTED, "ERROR: Non-session key");
   }
   catch(Error& e)
   {
      e.log();
      if (e.code_ != 0)
         SetLastError(e.code_);
      rv = FALSE;
   }
#endif // CSP_PASSTHROUGH

   END_API_CALL;
   return rv;
}
