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
/ File   :   Session.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "csp.h"
#include "Session.h"

namespace MCSP {

Session::Session(bool init/*= true*/)
   : doInit_(init), p11_(0), silent_(false), verifyContext_(false), 
      newKeyset_(false), machineKeyset_(false)
{
   if (doInit_)
   {
      lock_ = ::CreateMutex(NULL, FALSE, NULL); 

      // We generate a unique container for all of our attachments to the default
      // MS provider.  It gets deleted when this session is closed.
      BinStr uuid0;
      GenUUID(&uuid0);

      size_t provNameLen = strlen(PROVIDER_NAME);
      cryptProvUUID_.resize(provNameLen);
      memcpy(&cryptProvUUID_[0], PROVIDER_NAME, provNameLen);
      cryptProvUUID_.push_back('_'); cryptProvUUID_.push_back('_');
      cryptProvUUID_.resize(cryptProvUUID_.size() + uuid0.size());
      memcpy(&cryptProvUUID_[provNameLen+2], &uuid0[0], uuid0.size());
      cryptProvUUID_.push_back(0);

      if (!CryptAcquireContext(&cryptProv_, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
         Throw(NTE_PROVIDER_DLL_FAIL);

      if (g_state.p11->C_OpenSession(g_state.slot(), CKF_SERIAL_SESSION | CKF_RW_SESSION, 0, 0, &p11_) != CKR_OK)
      {
         // Try one more time in case the card was removed then put back
         if (g_state.p11->C_OpenSession(g_state.slot(), CKF_SERIAL_SESSION | CKF_RW_SESSION, 0, 0, &p11_) != CKR_OK)
            ThrowMsg(NTE_FAIL, "PKCS#11 session could not be opened");
      }

      LOG("PKCS#11 session: 0x%X\n", p11_);
   }
}

Session::~Session()
{
   if (doInit_)
   {
      LOG("Closing crypt session: 0x%X\n", cryptProv_);
      LOG("Closing P11 session: 0x%X\n", p11_);

      CryptReleaseContext(cryptProv_, 0);
      g_state.p11->C_CloseSession(p11_); // FIXME: check error?
      ::CloseHandle(lock_);
   }
}

void Session::parseFQCN(const char* fqcn0, BinStr* container_name, BinStr* reader_name)
{
   container_name->clear();
   reader_name->clear();

   if (fqcn0 == 0 || fqcn0[0] == 0)
   {
	  container_name->clear();
	  container_name->push_back(0);
      return;
   }

   BinStr fqcn = fqcn0;

   if (fqcn[0] == '\\' && fqcn[1] == '\\' && fqcn[2] == '.' && fqcn[3] == '\\')
   {
      char* c = strchr((char*)&fqcn[4], '\\');
      if (c != 0)
      {
         *c = 0;
         c++;
         (*container_name) = c;
      }

      (*reader_name) = (char*)&fqcn[4];
   }
   else
      (*container_name) = fqcn;

   LOG("ParseFQCN: container_name: \"%s\"\n", StringifyBin(*container_name, false).c_str());
   LOG("ParseFQCN: reader_name: \"%s\"\n", StringifyBin(*reader_name, false).c_str());
}

} // namespace MCSP
