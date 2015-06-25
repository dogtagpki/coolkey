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
/ File   :   cspx.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "csp.h"
#include <stdarg.h>
#include <time.h>
#include <sstream>

using namespace std;

namespace MCSP {

///////////////////////////////////////////////////////////////////////////////
// This cleans up messages that will be logged.  Linefeeds are converted to
// CR/LF and a timestamp is added.
//
// Parameters:
//  msg0 - Message to clean
//
// Returns:
//  string result
///////////////////////////////////////////////////////////////////////////////
string clean_flogf(const char* msg)
{
   ostringstream out;
   time_t t;

   time(&t);
   struct tm* time_s = localtime(&t);

   char timestr[32];
   sprintf(timestr, "%.2d/%.2d %.2d:%.2d:%.2d ", 
                  time_s->tm_mon+1, 
                  time_s->tm_mday, 
                  time_s->tm_hour, 
                  time_s->tm_min, 
                  time_s->tm_sec);

   out << timestr;

   char last = 0;
   for (size_t i = 0; msg[i] != 0x00; i++)
   {
      if (last == '\n')
         out << "               ";

      if (msg[i] == '\n' && last != '\r')
         out << '\r';

      out << msg[i];
      last = msg[i];
   }

   if (last != '\n')
      out << '\r' << '\n';

   return out.str();
}

///////////////////////////////////////////////////////////////////////////////
// Logs stuff
//
// Parameters:
//  msg - Message to log
//  ... - Variable parameters (like printf)
//
// Returns:
//  none
///////////////////////////////////////////////////////////////////////////////
void flogf(const char* msg0, ...)
{
   if (!g_state.logging())
      return;

   // Preserve error state
   DWORD lastErr = GetLastError();

   FILE* fp = fopen("C:\\CSPDEBUG.log", "ab");

   if (!fp)
   {
      fp = stderr;
      fprintf(fp, "ERROR: no log file");
   }

   string msg1 = clean_flogf(msg0);
   const char* msg = msg1.c_str();

   va_list args;
   va_start(args, msg0);
   vfprintf(fp, msg, args);
   va_end(args);

   if (fp == stderr)
      fflush(fp);
   else
      fclose(fp);

   SetLastError(lastErr);
}

///////////////////////////////////////////////////////////////////////////////
// Converts a BinStr binary string to hex or printable characters
//
// Parameters:
//  data    - Binary string to convert
//  hexMode - (optional) If hexMode is on then the return string will be hex
//            characters.  Otherwise it returns a string of printable
//            characters (unprintable characters are converted to '.').
//
// Returns:
//  string of hex data or printable characters
///////////////////////////////////////////////////////////////////////////////
string StringifyBin(const BinStr& data, bool hexMode)
{
   return StringifyBin((LPBYTE)&data[0], data.size(), hexMode);
}

///////////////////////////////////////////////////////////////////////////////
// Converts a BYTE binary string to hex or printable characters
//
// Parameters:
//  data    - Binary string to convert
//  len     - Length of string
//  hexMode - (optional) If hexMode is on then the return string will be hex
//            characters.  Otherwise it returns a string of printable
//            characters (unprintable characters are converted to '.').
//
// Returns:
//  string of hex data or printable characters
///////////////////////////////////////////////////////////////////////////////
string StringifyBin(const LPBYTE data, size_t len, bool hexMode)
{
   ostringstream out;

   if (hexMode)
   {
      // ostringstream can do hex, but the .width flag doesn't
      // work in Microsoft's implementation (!)
      char hex[32];
      for (size_t i = 0; i < len; i++)
      {
         sprintf(hex, "%.2X", data[i]);
         out << hex;
      }
   }
   else
   {
      for (size_t i = 0; i < len; i++)
      {
         if (isgraph(data[i]) || data[i] == ' ')
            out << data[i];
         else
            out << '.';
      }
   }

   return out.str();
}

///////////////////////////////////////////////////////////////////////////////
// Convert a CryptProvParam to text
//
// Parameters:
//  param - Parameter value
//
// Returns:
//  string
///////////////////////////////////////////////////////////////////////////////
string StringifyProvParam(DWORD param)
{
   switch(param)
   {
   case PP_CONTAINER:
      return "PP_CONTAINER";
      break;
   case PP_ENUMALGS:
      return "PP_ENUMALGS";
      break;
   case PP_ENUMALGS_EX:
      return "PP_ENUMALGS_EX";
      break;
   case PP_ENUMCONTAINERS:
      return "PP_ENUMCONTAINERS";
      break;
   case PP_IMPTYPE:
      return "PP_IMPTYPE";
      break;
   case PP_NAME:
      return "PP_NAME";
      break;
   case PP_VERSION:
      return "PP_VERSION";
      break;
   case PP_SIG_KEYSIZE_INC:
      return "PP_SIG_KEYSIZE_INC";
      break;
   case PP_KEYX_KEYSIZE_INC:
      return "PP_KEYX_KEYSIZE_INC";
      break;
   case PP_KEYSET_SEC_DESCR:
      return "PP_KEYSET_SEC_DESCR";
      break;
   case PP_UNIQUE_CONTAINER:
      return "PP_UNIQUE_CONTAINER";
      break;
   case PP_PROVTYPE:
      return "PP_PROVTYPE";
      break;
   default:
      return "PP_UNKNOWN";
      break;
   }
}

///////////////////////////////////////////////////////////////////////////////
// Converts AcquireContext flags to text
//
// Parameters:
//  param - Parameter value
//
// Returns:
//  string
///////////////////////////////////////////////////////////////////////////////
string StringifyAquireFlags(DWORD param)
{
   string rv;

   if (param & CRYPT_VERIFYCONTEXT)
      rv += "CRYPT_VERIFYCONTEXT | ";

   if (param & CRYPT_NEWKEYSET)
      rv += "CRYPT_NEWKEYSET | ";

   if (param & CRYPT_MACHINE_KEYSET)
      rv += "CRYPT_MACHINE_KEYSET | ";

   if (param & CRYPT_DELETEKEYSET)
      rv += "CRYPT_DELETEKEYSET | ";

   if (param & CRYPT_SILENT)
      rv += "CRYPT_SILENT | ";

   return rv;
}

///////////////////////////////////////////////////////////////////////////////
// Converts CALG_XXXX algorithm to text
//
// Parameters:
//  id - Algorithm ID
//
// Returns:
//  string
///////////////////////////////////////////////////////////////////////////////
string StringifyCALG(ALG_ID id)
{
   switch(id)
   {
   case CALG_MD2:
      return "CALG_MD2";
   case CALG_MD4:
      return "CALG_MD4";
   case CALG_MD5:
      return "CALG_MD5";
   case CALG_SHA1:
      return "CALG_SHA1";
   case CALG_MAC:
      return "CALG_MAC";
   case CALG_RSA_SIGN:
      return "CALG_RSA_SIGN";
   case CALG_DSS_SIGN:
      return "CALG_DSS_SIGN";
   case CALG_NO_SIGN:
      return "CALG_NO_SIGN";
   case CALG_RSA_KEYX:
      return "CALG_RSA_KEYX";
   case CALG_DES:
      return "CALG_DES";
   case CALG_3DES_112:
      return "CALG_3DES_112";
   case CALG_3DES:
      return "CALG_3DES";
   case CALG_DESX:
      return "CALG_DESX";
   case CALG_RC2:
      return "CALG_RC2";
   case CALG_RC4:
      return "CALG_RC4";
   case CALG_SEAL:
      return "CALG_SEAL";
   case CALG_DH_SF:
      return "CALG_DH_SF";
   case CALG_DH_EPHEM:
      return "CALG_DH_EPHEM";
   case CALG_AGREEDKEY_ANY:
      return "CALG_AGREEDKEY_ANY";
   case CALG_KEA_KEYX:
      return "CALG_KEA_KEYX";
   case CALG_HUGHES_MD5:
      return "CALG_HUGHES_MD5";
   case CALG_SKIPJACK:
      return "CALG_SKIPJACK";
   case CALG_TEK:
      return "CALG_TEK";
   case CALG_CYLINK_MEK:
      return "CALG_CYLINK_MEK";
   case CALG_SSL3_SHAMD5:
      return "CALG_SSL3_SHAMD5";
   case CALG_SSL3_MASTER:
      return "CALG_SSL3_MASTER";
   case CALG_SCHANNEL_MASTER_HASH:
      return "CALG_SCHANNEL_MASTER_HASH";
   case CALG_SCHANNEL_MAC_KEY:
      return "CALG_SCHANNEL_MAC_KEY";
   case CALG_SCHANNEL_ENC_KEY:
      return "CALG_SCHANNEL_ENC_KEY";
   case CALG_PCT1_MASTER:
      return "CALG_PCT1_MASTER";
   case CALG_SSL2_MASTER:
      return "CALG_SSL2_MASTER";
   case CALG_TLS1_MASTER:
      return "CALG_TLS1_MASTER";
   case CALG_RC5:
      return "CALG_RC5";
   case CALG_HMAC:
      return "CALG_HMAC";
   case CALG_TLS1PRF:
      return "CALG_TLS1PRF";
   case CALG_HASH_REPLACE_OWF:
      return "CALG_HASH_REPLACE_OWF";
   case CALG_AES_128:
      return "CALG_AES_128";
   case CALG_AES_192:
      return "CALG_AES_192";
   case CALG_AES_256:
      return "CALG_AES_256";
   case CALG_AES:
      return "CALG_AES";
   case AT_KEYEXCHANGE:
      return "AT_KEYEXCHANGE";
   case AT_SIGNATURE:
      return "AT_SIGNATURE";
   default:
      {
         char buf[256];
         sprintf(buf, "UNKNOWN (0x%X)", id);
         return buf;
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
// Used with GetProvParam and PP_ENUMALGS
//
// Parameters:
//  context    - CSP context
//  dwFlags    - Flags from GetProvParam call
//  pbData     - Same as GetProvParam call
//  pcbDataLen - Same as GetProvParam call
//
// Returns:
//  none
///////////////////////////////////////////////////////////////////////////////
void GetProvParam_PP_ENUMALGS(Session* context, DWORD dwFlags,
                              OUT LPBYTE pbData,
                              IN OUT LPDWORD pcbDataLen)
{
   static int algCursor = 0;
   PROV_ENUMALGS output;

   static struct
   {
      char* name;
      ALG_ID id;
      DWORD bitLen;
   }
   algs[] = { { "MD5",  CALG_MD5,  128 },
              { "SHA1", CALG_SHA1, 160 },
              { "DES",  CALG_DES,  56  },
              { "3DES", CALG_3DES, 168 },
              { "RC2",  CALG_RC2,  128 },
              { NULL } };

   LOG("GetProvParam_PP_ENUMALGS called\n");
   if (dwFlags & CRYPT_FIRST)
      algCursor = 0;

   if (algs[algCursor].name == NULL)
      Throw(ERROR_NO_MORE_ITEMS);
   else
   {
      output.aiAlgid = algs[algCursor].id;
      output.dwBitLen = algs[algCursor].bitLen;
      output.dwNameLen = (DWORD)strlen(algs[algCursor].name) + 1;
      strcpy(output.szName, algs[algCursor].name);

      PutDataIntoBuffer(pbData, pcbDataLen, reinterpret_cast<LPBYTE>(&output), sizeof(output));
   }

   LOG("aiAlgid:0x%X dwBitLen:%u dwNameLen:%u szName:\"%s\"\n",
      output.aiAlgid, output.dwBitLen, output.dwNameLen, output.szName);

   algCursor++;
}

void GetProvParam_PP_ENUMALGS_EX(Session* context, DWORD dwFlags,
                                 OUT LPBYTE pbData,
                                 IN OUT LPDWORD pcbDataLen)
{
   static int algCursor = 0;
   PROV_ENUMALGS_EX output;

   static struct
   {
      char* name;
      ALG_ID id;
      DWORD defLen;
      DWORD minLen;
      DWORD maxLen;
   }                                    // def   min  max
   algs[] = { { "MD5",      CALG_MD5,      128,  128, 128  },
              { "SHA1",     CALG_SHA1,     160,  160, 160  },
              { "RSA_SIGN", CALG_RSA_SIGN, 1024, 512, 1024 },
              { "RSA_KEYX", CALG_RSA_KEYX, 1024, 512, 1024 },
              { "DES",      CALG_DES,      56,   56,  56   },
              { "3DES",     CALG_3DES,     168,  168, 168  },
              { "RC2",      CALG_RC2,      128,  40,  128  },
              { NULL } };

   LOG("GetProvParam_PP_ENUMALGS_EX called\n");

   if (dwFlags & CRYPT_FIRST)
      algCursor = 0;

   if (algs[algCursor].name == NULL)
      Throw(ERROR_NO_MORE_ITEMS);
   else
   {
      output.aiAlgid = algs[algCursor].id;
      output.dwDefaultLen = algs[algCursor].defLen;
      output.dwMinLen = algs[algCursor].minLen;
      output.dwMaxLen = algs[algCursor].maxLen;
      output.dwProtocols = 1;
      output.dwNameLen = (DWORD)strlen(algs[algCursor].name) + 1;
      strcpy(output.szName, algs[algCursor].name);
      output.dwLongNameLen = (DWORD)strlen(algs[algCursor].name) + 1;
      strcpy(output.szLongName, algs[algCursor].name);

      PutDataIntoBuffer(pbData, pcbDataLen, reinterpret_cast<LPBYTE>(&output), sizeof(output));
   }

   LOG("aiAlgid:0x%X dwDefaultLen:%u dwMinLen:%u dwMaxLen:%u dwProtocols:%u dwNameLen:%u szName:\"%s\"\n",
      output.aiAlgid, 
      output.dwDefaultLen, 
      output.dwMinLen, 
      output.dwMaxLen, 
      output.dwProtocols, 
      output.dwNameLen, 
      output.szName);

   algCursor++;
}

///////////////////////////////////////////////////////////////////////////////
// Used with GetProvParam and PP_ENUMCONTAINERS
//
// Parameters:
//  context    - CSP context
//  dwFlags    - Flags from GetProvParam call
//  pbData     - Same as GetProvParam call
//  pcbDataLen - Same as GetProvParam call
//
// Returns:
//  none
///////////////////////////////////////////////////////////////////////////////
void GetProvParam_PP_ENUMCONTAINERS(Session* context, DWORD dwFlags,
                                    OUT LPBYTE pbData,
                                    IN OUT LPDWORD pcbDataLen)
{
   LOG("GetProvParam_PP_ENUMCONTAINERS called\n");

   if (dwFlags & CRYPT_FIRST)
   {
      LOG("ENUMCONTAINERS resetting container enumeration\n");
      context->containers_.clear();
      context->containerItr_ = context->containers_.begin();

      // Init search (all objects)
      if (g_state.p11->C_FindObjectsInit(context->p11_, 0, 0) != CKR_OK)
         ThrowMsg(ERROR_NO_MORE_ITEMS, "C_FindObjectsInit failed");

      CK_ULONG count = 1;
      CK_OBJECT_HANDLE hObj;

      while(true)
      {
         if (CKR_OK != g_state.p11->C_FindObjects(context->p11_, &hObj, 1, &count) || count == 0)
         {
            // No more objects (or any other error)
            g_state.p11->C_FindObjectsFinal(context->p11_);
            break;
         }
         else
         {
            CK_ATTRIBUTE pTemplate = { CKA_ID, 0, 0 };

            // Get the length
            if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &pTemplate, 1) != CKR_OK)
               continue;

            // Get the data
            BinStr id;
            id.resize(pTemplate.ulValueLen);
            pTemplate.pValue = &id[0];
            if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &pTemplate, 1) != CKR_OK)
               continue;

            id.BinToHex();
            id.push_back(0);

            context->containers_.insert(id);
         }
      }

      // Set it again in case of poor STL implementaion
      context->containerItr_ = context->containers_.begin();
   }

   if (context->containerItr_ == context->containers_.end())
      Throw(ERROR_NO_MORE_ITEMS);
   
   PutDataIntoBuffer(pbData, pcbDataLen, &(*context->containerItr_)[0], 
         context->containerItr_->size());

   if (pbData)
      context->containerItr_++;
}

///////////////////////////////////////////////////////////////////////////////
// Checks input and output settings and returns data and/or length
//
// Parameters:
//  dest      - Destination buffer
//  destLen   - Destination buffer size
//  source    - Source buffer
//  sourceLen - Source buffer size
//
// Returns:
//  none - Throws exception on bad data
///////////////////////////////////////////////////////////////////////////////
void PutDataIntoBuffer(LPBYTE dest, LPDWORD destLen, const LPBYTE source,
                       DWORD sourceLen)
{
   if (destLen == NULL)
      Throw(ERROR_MORE_DATA);
   else if (dest == NULL)
      *destLen = sourceLen;
   else if (*destLen < sourceLen)
      Throw(ERROR_MORE_DATA);
   else
   {
      memcpy(dest, source, sourceLen);
      *destLen = sourceLen;
   }
}

///////////////////////////////////////////////////////////////////////////////
// Reverses a BinStr
//
// Parameters:
//  buf - String to reverse
//
// Returns:
//  none
///////////////////////////////////////////////////////////////////////////////
void Reverse(BinStr* buf)
{
   Reverse(&(*buf)[0], buf->size());
}

///////////////////////////////////////////////////////////////////////////////
// Reverses a BYTE string
//
// Parameters:
//  buf - String to reverse
//  len - Length of string
//
// Returns:
//  none
///////////////////////////////////////////////////////////////////////////////
void Reverse(LPBYTE buf, size_t len)
{
   size_t pos, maxPos = len / 2 - 1;

   for (pos = 0; pos <= maxPos; pos++)
   {
      char temp;

      temp = buf[pos];
      buf[pos] = buf[len - 1 - pos];
      buf[len - 1 - pos] = temp;
   }
}

///////////////////////////////////////////////////////////////////////////////
// If there are any logon certs this returns the last one.
// If there are no logon certs then this just returns the last cert on the
// card.
//
// Parameters:
//  context   - CSP context
//  phCert    - CK_OBJECT_HANDLE of found cert
//  container - Container name that cert exists in
//
// Returns:
//  FALSE on failure
///////////////////////////////////////////////////////////////////////////////
bool FindDefaultCert(Session* context, CK_OBJECT_HANDLE* phCert, BinStr* container)
{
   bool rv = true;
   *phCert = 0;

   CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
   CK_ATTRIBUTE attrib = { CKA_CLASS, &objClass, sizeof(objClass) };

   LOG("FindDefaultCert. \n");

   // start object search for all certificates
   if (g_state.p11->C_FindObjectsInit(context->p11_, &attrib, 1) != CKR_OK)
   {
      LOG("C_FindObjectsInit failed\n");
      return false;
   }

   try
   {
      bool haveLogonCert = false;

      // Set up the structure so we can get the cert's CKA_ID and CKA_VALUE
      CK_ATTRIBUTE attrib[] = {
         { CKA_ID, 0, 0 },
         { CKA_VALUE, 0, 0 }
      };

      // Loop through all certs
      CK_ULONG ulNumFound = 1;
      while (ulNumFound > 0)
      {
         LOG("FindDefaultCert. Top of while loop, through certs. \n");

         CK_OBJECT_HANDLE hCert;
         if (g_state.p11->C_FindObjects(context->p11_, &hCert, 1, &ulNumFound) != CKR_OK)
            ThrowMsg(0, "C_FindObjects failed\n");

         if (ulNumFound == 0)
            break;

         LOG("FindDefaultCert. Num Certs found %d hcert %d. \n",ulNumFound,hCert);
         // First we want the CKA_ID and CKA_VALUE lengths
         attrib[0].pValue = 0;
         attrib[1].pValue = 0;
         if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, attrib, sizeof(attrib)/sizeof(CK_ATTRIBUTE)) != CKR_OK)
            continue;

         BinStr ckaid(attrib[0].ulValueLen);
         attrib[0].pValue = &ckaid[0];
         BinStr cert(attrib[1].ulValueLen);
         attrib[1].pValue = &cert[0];

         // Get the CKA_ID and CKA_VALUE
         if (g_state.p11->C_GetAttributeValue(context->p11_, hCert, attrib, sizeof(attrib)/sizeof(CK_ATTRIBUTE)) != CKR_OK)
            continue;


         if (IsCACert(cert))
            continue;

         vector<string> ext;
         GetExtKeyUsageFromCert(&ext, cert);

         DWORD i;
         for (i = 0; i < ext.size(); i++)
         {
            // Logon or enrollment agent
            if (ext[i] == "1.3.6.1.4.1.311.20.2.2" || ext[i] == "1.3.6.1.4.1.311.20.2.1")
            {
               haveLogonCert = true;
               container->swap(ckaid);
               *phCert = hCert;
               LOG("FindDefaultCert. Setting default cert because proper extension found. \n");
               break;
            }
         }

         if (i >= ext.size() && !haveLogonCert)
         {
            container->swap(ckaid);
            LOG("FindDefaultCert Setting default cert because not a login cert. %d \n",hCert);
            *phCert = hCert;
         }
      }
   }
   catch (Error&)
   {
      *phCert = 0;
   }

   g_state.p11->C_FindObjectsFinal(context->p11_);
   
   if (*phCert)
      return true;
   else 
      return false;
}

///////////////////////////////////////////////////////////////////////////////
// Finds last container name on card
//
// Parameters:
//  context   - CSP context
//  phCert    - CK_OBJECT_HANDLE of last obj
//  container - Container name of last container
//
// Returns:
//  FALSE on failure
///////////////////////////////////////////////////////////////////////////////
bool FindLastContainer(Session* context, CK_OBJECT_HANDLE* phObj, BinStr* container)
{
   bool rv = true;
   *phObj = 0;

   // start object search for all objects
   if (g_state.p11->C_FindObjectsInit(context->p11_, 0, 0) != CKR_OK)
   {
      LOG("C_FindObjectsInit failed\n");
      return false;
   }

   try
   {
      CK_ATTRIBUTE attrib = { CKA_ID, 0, 0 };

      CK_ULONG ulNumFound = 1;
      while (ulNumFound > 0)
      {
         CK_OBJECT_HANDLE hObj;
         if (g_state.p11->C_FindObjects(context->p11_, &hObj, 1, &ulNumFound) != CKR_OK)
            ThrowMsg(0, "C_FindObjects failed\n");

         if (ulNumFound == 0)
            break;

         attrib.pValue = 0;
         if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &attrib, 1) != CKR_OK)
            continue;

         BinStr ckaid(attrib.ulValueLen);
         attrib.pValue = &ckaid[0];

         if (g_state.p11->C_GetAttributeValue(context->p11_, hObj, &attrib, 1) != CKR_OK)
            continue;

         container->swap(ckaid);
         *phObj = hObj;
      }
   }
   catch (Error&)
   {
      *phObj = 0;
   }

   g_state.p11->C_FindObjectsFinal(context->p11_);
   
   if (*phObj)
      return true;
   else 
      return false;
}

///////////////////////////////////////////////////////////////////////////////
// Finds a single object (first matching CKA_CLASS) in the current container
//
// Parameters:
//  context   - CSP context
//  phCert    - CK_OBJECT_HANDLE of found object
//  objClass  - CKA_CLASS of object to find
//
// Returns:
//  FALSE on failure
///////////////////////////////////////////////////////////////////////////////
bool FindObject(Session* context, CK_OBJECT_HANDLE* phObj, CK_OBJECT_CLASS objClass)
{
   bool rv;

   CK_ATTRIBUTE search[] = {
      { CKA_ID, &context->CKAID_[0], context->CKAID_.size() },
      { CKA_CLASS, &objClass, sizeof(objClass) }
   };

   LOG("FindObject() CLA_CLASS:0x%X CKA_ID:%s \"%s\"\n", objClass, 
      StringifyBin(context->CKAID_).c_str(), StringifyBin(context->CKAID_, false).c_str());

   // start object search
   if (g_state.p11->C_FindObjectsInit(context->p11_, search, sizeof(search)/sizeof(CK_ATTRIBUTE)) != CKR_OK)
   {
      LOG("C_FindObjectsInit failed\n");
      rv = false;
   }
   else
   {
      // do the search
      CK_ULONG ulNumFound = 0;
      CK_OBJECT_HANDLE hObj;
      if (g_state.p11->C_FindObjects(context->p11_, &hObj, 1, &ulNumFound) != CKR_OK)
      {
         LOG("C_FindObjects failed\n");
         rv = false;
      }
      else if (ulNumFound < 1)
         rv = false;
      else
      {
         if (phObj)
            *phObj = hObj;

         rv = true;
      }

      g_state.p11->C_FindObjectsFinal(context->p11_);
   }
   
   LOG("FindObject returned: %s\n", rv ? "TRUE" : "FALSE");
   return rv;
}

///////////////////////////////////////////////////////////////////////////////
// Returns length of a ASN.1 SEQUENCE-OF.  Note that this function is extremely
// dangerous.  If non-ASN.1 encoded data is passed in then bad things could
// happen.
//
// Parameters:
//  buf        - BYTE buffer
//  withHeader - (default: true) Returns length with ASN.1 header length
//               included
//
// Returns:
//  length
///////////////////////////////////////////////////////////////////////////////
CK_ULONG ASN1Len(const CK_BYTE* buf, bool withHeader)
{
   // Make a very simplistic check for valid data since this
   // function is inherently dangerous
   if (buf[0] != 0x30)
      return 0;

   CK_ULONG used_length = 1; // Skip the tag
   CK_ULONG data_length = buf[used_length++];;

   if (data_length & 0x80) 
   {
      CK_ULONG len_count = data_length & 0x7f;
      data_length = 0;
      while (len_count-- > 0) 
         data_length = (data_length << 8) | buf[used_length++];
    }

   if (withHeader)
      return data_length + used_length;
   else
      return data_length;
}

///////////////////////////////////////////////////////////////////////////////
// Returns the modulus and exponent in big-endian format
//
// Parameters:
//  context  - CSP context
//  modulus  - Output of modulus
//  exponent - Output of exponent
//  cert     - Certificate to extract from (raw binary)
//
// Returns:
//  FALSE on failure
///////////////////////////////////////////////////////////////////////////////
bool GetModulusFromCert(Session* context, BinStr* modulus, BinStr* exponent, const BinStr& cert)
{
   bool rv = true;

   CRYPT_SEQUENCE_OF_ANY* modseq = 0;
   CRYPT_INTEGER_BLOB* mod = 0;
   PCCERT_CONTEXT certContext = 0;

   try
   {
       certContext = 
         CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            &cert[0], cert.size());

      if (certContext == 0)
         ThrowMsg(0, "CertCreateCertificateContext failed");

      HCRYPTKEY hKey;
      if (!CryptImportPublicKeyInfo(context->cryptProv_, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
         &certContext->pCertInfo->SubjectPublicKeyInfo, &hKey))
         Throw(0);

      DWORD dwDataLen;
      if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, 0, &dwDataLen))
         Throw(0);
      BinStr blob(dwDataLen);
      if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, &blob[0], &dwDataLen))
         Throw(0);

      BLOBHEADER* header = (BLOBHEADER*)&blob[0];
      RSAPUBKEY* rsakey = (RSAPUBKEY*)&blob[sizeof(BLOBHEADER)];
      
      modulus->resize(rsakey->bitlen/8);
      exponent->resize(sizeof(rsakey->pubexp));

      memcpy(&(*modulus)[0], &blob[sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)], rsakey->bitlen/8);
      memcpy(&(*exponent)[0], &rsakey->pubexp, sizeof(rsakey->pubexp));

      while (exponent->back() == 0x00)
         exponent->pop_back();

      Reverse(modulus);
      Reverse(exponent);
   }
   catch (Error&)
   {
      rv = false;
   }

   if (certContext)
      CertFreeCertificateContext(certContext);

   if (modseq)
      LocalFree(modseq);

   if (mod)
      LocalFree(mod);

   return rv;
}

///////////////////////////////////////////////////////////////////////////////
// Fills an array with the extended key usage OID's
//
// Parameters:
//  ext  - Array of returned strings
//  cert - Certificate data (raw binary)
//
// Returns:
//  FALSE on failure
///////////////////////////////////////////////////////////////////////////////
bool GetExtKeyUsageFromCert(vector<string>* ext, const BinStr& cert)
{
   bool rv = true;

   CRYPT_SEQUENCE_OF_ANY* extusage = 0;
   PCCERT_CONTEXT certContext = 0;

   try
   {
      certContext = 
         CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            &cert[0], cert.size());

      if (certContext == 0)
         ThrowMsg(0, "CertCreateCertificateContext failed");

      CERT_ENHKEY_USAGE* usage;
      DWORD usageSize;
      if (!CertGetEnhancedKeyUsage(certContext, 0, 0, &usageSize))
         Throw(0);

      usage = (CERT_ENHKEY_USAGE*)new char[usageSize];
      if (!CertGetEnhancedKeyUsage(certContext, 0, usage, &usageSize))
         Throw(0);

      ext->resize(usage->cUsageIdentifier);

      for (DWORD i = 0; i < usage->cUsageIdentifier; i++)
         (*ext)[i] = usage->rgpszUsageIdentifier[i];
   }
   catch (Error&)
   {
      rv = false;
   }

   if (certContext)
      CertFreeCertificateContext(certContext);

   if (extusage)
      LocalFree(extusage);

   return rv;
}

bool IsCACert(const BinStr& cert)
{
   bool rv = false;
   DWORD cbInfo= 0;
   
   PCCERT_CONTEXT certContext = 0;

   LOG("IsCACert cert %p size %d \n", &cert,cert.size());

   cbInfo = sizeof(CERT_BASIC_CONSTRAINTS2_INFO);

   PCERT_BASIC_CONSTRAINTS2_INFO pInfo = 
      (PCERT_BASIC_CONSTRAINTS2_INFO) LocalAlloc(LPTR,cbInfo);

   if (!pInfo)
      return rv;

   try
   {
      certContext = 
         CertCreateCertificateContext(X509_ASN_ENCODING  | PKCS_7_ASN_ENCODING,
            &cert[0], cert.size());

      if (certContext == 0)
         ThrowMsg(0, "CertCreateCertificateContext failed");

     
      PCERT_EXTENSION pBC = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
         certContext->pCertInfo->cExtension, certContext->pCertInfo->rgExtension);

      if (!pBC)
         ThrowMsg(0,"No BASIC_CONSTRAINT extension.");

      DWORD cbDecoded = cbInfo;
     
      BOOL dResult = CryptDecodeObject(X509_ASN_ENCODING |PKCS_7_ASN_ENCODING  ,         szOID_BASIC_CONSTRAINTS2,
         pBC->Value.pbData, pBC->Value.cbData, 0, pInfo,&cbDecoded);

      if (!dResult)
      {

         DWORD error = GetLastError();
           		  
         LOG("IsCACert CryptDecodeObject failed! error 0x%lx \n",error);

         ThrowMsg(0,"CryptDecodeObject failed");
      }

      rv = (bool) pInfo->fCA; 

      LOG("IsCACert returning  fCA %ld fPathLenConstraint %ld dwPathLenConstraint %lu .\n",pInfo->fCA,pInfo->fPathLenConstraint,pInfo->dwPathLenConstraint);
   }
   catch (Error&)
   {
      rv = false;
   }

   if (certContext)
      CertFreeCertificateContext(certContext);

   if (pInfo)
      LocalFree(pInfo);
   
   return rv;
}

string GetCurrentExecutable()
{
   TCHAR szModulePath[MAX_PATH];

   if (GetModuleFileName(0, szModulePath, sizeof(szModulePath) / sizeof(TCHAR)) == 0)
      return "";
   else
      return string(szModulePath);
}

string GetCurrentDLL()
{
   TCHAR szModulePath[MAX_PATH];

   if (GetModuleFileName(g_hModule, szModulePath, sizeof(szModulePath) / sizeof(TCHAR)) == 0)
      return "";
   else
      return string(szModulePath);
}

} // namespace MCSP

// Microsoft helpers for handling session keys
namespace CryptoHelper {

BOOL CreatePrivateExponentOneKey(HCRYPTPROV hProv,
                                 DWORD dwKeySpec,
                                 HCRYPTKEY *hPrivateKey)
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   DWORD n;
   LPBYTE keyblob = NULL;
   DWORD dwkeyblob;
   DWORD dwBitLen;
   BYTE *ptr;

   __try
   {
      *hPrivateKey = 0;

      if ((dwKeySpec != AT_KEYEXCHANGE) && (dwKeySpec != AT_SIGNATURE))  __leave;

      // Generate the private key
      fResult = CryptGenKey(hProv, dwKeySpec, CRYPT_EXPORTABLE, hPrivateKey);
      if (!fResult) __leave;

      // Export the private key, we'll convert it to a private
      // exponent of one key
      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
      if (!fResult) __leave;      

      keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
      if (!keyblob) __leave;

      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
      if (!fResult) __leave;


      CryptDestroyKey(*hPrivateKey);
      *hPrivateKey = 0;

      // Get the bit length of the key
      memcpy(&dwBitLen, &keyblob[12], 4);      

      // Modify the Exponent in Key BLOB format
      // Key BLOB format is documented in SDK

      // Convert pubexp in rsapubkey to 1
      ptr = &keyblob[16];
      for (n = 0; n < 4; n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip pubexp
      ptr += 4;
      // Skip modulus, prime1, prime2
      ptr += (dwBitLen/8);
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert exponent1 to 1
      for (n = 0; n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent1
      ptr += (dwBitLen/16);

      // Convert exponent2 to 1
      for (n = 0; n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent2, coefficient
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert privateExponent to 1
      for (n = 0; n < (dwBitLen/8); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }
      
      // Import the exponent-of-one private key.      
      if (!CryptImportKey(hProv, keyblob, dwkeyblob, 0, 0, hPrivateKey))
      {                 
         __leave;
      }

      fReturn = TRUE;
   }
   __finally
   {
      if (keyblob) LocalFree(keyblob);

      if (!fReturn)
      {
         if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
      }
   }

   return fReturn;
}

BOOL ExportPlainSessionBlob(HCRYPTKEY hPublicKey,
                            HCRYPTKEY hSessionKey,
                            LPBYTE *pbKeyMaterial ,
                            DWORD *dwKeyMaterial )
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   DWORD dwSize, n;
   LPBYTE pbSessionBlob = NULL;
   DWORD dwSessionBlob;
   LPBYTE pbPtr;

   __try
   {
      *pbKeyMaterial  = NULL;
      *dwKeyMaterial  = 0;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, NULL, &dwSessionBlob );
      if (!fResult) __leave;

      pbSessionBlob  = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob );
      if (!pbSessionBlob) __leave;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, pbSessionBlob , &dwSessionBlob );
      if (!fResult) __leave;

      // Get session key size in bits
      dwSize = sizeof(DWORD);
      fResult = CryptGetKeyParam(hSessionKey, KP_KEYLEN, (LPBYTE)dwKeyMaterial, &dwSize, 0);
      if (!fResult) __leave;

      // Get the number of bytes and allocate buffer
      *dwKeyMaterial /= 8;
      *pbKeyMaterial = (LPBYTE)LocalAlloc(LPTR, *dwKeyMaterial);
      if (!*pbKeyMaterial) __leave;

      // Skip the header
      pbPtr = pbSessionBlob;
      pbPtr += sizeof(BLOBHEADER);
      pbPtr += sizeof(ALG_ID);

      // We are at the beginning of the key
      // but we need to start at the end since 
      // it's reversed
      pbPtr += (*dwKeyMaterial - 1);
      
      // Copy the raw key into our return buffer      
      for (n = 0; n < *dwKeyMaterial; n++)
      {
         (*pbKeyMaterial)[n] = *pbPtr;
         pbPtr--;
      }      
      
      fReturn = TRUE;
   }
   __finally
   {
      if (pbSessionBlob) LocalFree(pbSessionBlob);

      if ((!fReturn) && (*pbKeyMaterial ))
      {
         LocalFree(*pbKeyMaterial );
         *pbKeyMaterial  = NULL;
         *dwKeyMaterial  = 0;
      }
   }

   return fReturn;
}


BOOL ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial ,
                            DWORD dwKeyMaterial ,
                            HCRYPTKEY *hSessionKey)
{
   BOOL fResult;   
   BOOL fReturn = FALSE;
   BOOL fFound = FALSE;
   LPBYTE pbSessionBlob = NULL;
   DWORD dwSessionBlob, dwSize, n;
   DWORD dwPublicKeySize;
   DWORD dwProvSessionKeySize;
   ALG_ID dwPrivKeyAlg;
   LPBYTE pbPtr; 
   DWORD dwFlags = CRYPT_FIRST;
   PROV_ENUMALGS_EX ProvEnum;
   HCRYPTKEY hTempKey = 0;

   __try
   {
      // Double check to see if this provider supports this algorithm
      // and key size
      do
      {        
         dwSize = sizeof(ProvEnum);
         fResult = CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum,
                                     &dwSize, dwFlags);
         if (!fResult) break;

         dwFlags = 0;

         if (ProvEnum.aiAlgid == dwAlgId) fFound = TRUE;
                                     
      } while (!fFound);

      if (!fFound) __leave;

      // We have to get the key size(including padding)
      // from an HCRYPTKEY handle.  PP_ENUMALGS_EX contains
      // the key size without the padding so we can't use it.
      fResult = CryptGenKey(hProv, dwAlgId, 0, &hTempKey);
      if (!fResult) __leave;
      
      dwSize = sizeof(DWORD);
      fResult = CryptGetKeyParam(hTempKey, KP_KEYLEN, (LPBYTE)&dwProvSessionKeySize,
                                 &dwSize, 0);
      if (!fResult) __leave;      
      CryptDestroyKey(hTempKey);
      hTempKey = 0;

      // Our key is too big, leave
      if ((dwKeyMaterial * 8) > dwProvSessionKeySize) __leave;

      // Get private key's algorithm
      dwSize = sizeof(ALG_ID);
      fResult = CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0);
      if (!fResult) __leave;

      // Get private key's length in bits
      dwSize = sizeof(DWORD);
      fResult = CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0);
      if (!fResult) __leave;

      // calculate Simple blob's length
      dwSessionBlob = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

      // allocate simple blob buffer
      pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob);
      if (!pbSessionBlob) __leave;

      pbPtr = pbSessionBlob;

      // SIMPLEBLOB Format is documented in SDK
      // Copy header to buffer
      ((BLOBHEADER *)pbPtr)->bType = SIMPLEBLOB;
      ((BLOBHEADER *)pbPtr)->bVersion = 2;
      ((BLOBHEADER *)pbPtr)->reserved = 0;
      ((BLOBHEADER *)pbPtr)->aiKeyAlg = dwAlgId;
      pbPtr += sizeof(BLOBHEADER);

      // Copy private key algorithm to buffer
      *((DWORD *)pbPtr) = dwPrivKeyAlg;
      pbPtr += sizeof(ALG_ID);

      // Place the key material in reverse order
      for (n = 0; n < dwKeyMaterial; n++)
      {
         pbPtr[n] = pbKeyMaterial[dwKeyMaterial-n-1];
      }
     
      // 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end.
      dwSize = dwSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + dwKeyMaterial + 3);
      pbPtr += (dwKeyMaterial+1);

      // Generate random data for the rest of the buffer
      // (except that last two bytes)
      fResult = CryptGenRandom(hProv, dwSize, pbPtr);
      if (!fResult) __leave;

      for (n = 0; n < dwSize; n++)
      {
         if (pbPtr[n] == 0) pbPtr[n] = 1;
      }

      pbSessionBlob[dwSessionBlob - 2] = 2;

      fResult = CryptImportKey(hProv, pbSessionBlob , dwSessionBlob, 
                               hPrivateKey, CRYPT_EXPORTABLE, hSessionKey);
      if (!fResult) __leave;

      fReturn = TRUE;           
   }
   __finally
   {
      if (hTempKey) CryptDestroyKey(hTempKey);
      if (pbSessionBlob) LocalFree(pbSessionBlob);
   }
   
   return fReturn;
}

} // namespace CryptoHelper
