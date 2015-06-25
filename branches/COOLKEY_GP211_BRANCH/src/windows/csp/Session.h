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
/ File   :   Session.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_SESSION_H__
#define __INCLUDE_SESSION_H__

#include "BinStr.h"
#include <set>

namespace MCSP {

class Session
{
private:
   HANDLE lock_;

public:
   // FIXME: make these private and add accessors...
   bool doInit_;
   CK_SESSION_HANDLE p11_;
   HCRYPTPROV cryptProv_;
   bool silent_;
   bool verifyContext_;
   bool newKeyset_;
   bool machineKeyset_;
   BinStr readerName_;     // NULL terminated; CSP friendly
   BinStr containerName_;  // NULL terminated; CSP friendly
   BinStr CKAID_;          // Real container name; could be binary; not NULL terminated
   BinStr cryptProvUUID_;

   std::set<BinStr> containers_;
   std::set<BinStr>::iterator containerItr_;

   Session(bool init = true);
   ~Session();

   void lock()
      { ::WaitForSingleObject(lock_, INFINITE); }

   void unlock()
      { ::ReleaseMutex(lock_); }

   static void parseFQCN(const char* fqcn, BinStr* container_name, BinStr* reader_name);

   // Little helper that performs automatic thread locking (see csp.cpp for usage)
   class Ptr
   {
   private:
      Session *s_;
   public:
      Ptr(Session* s) { s_ = s; s_->lock(); }
      ~Ptr() { s_->unlock(); }
      Session* operator ->() { return s_; }
      operator Session*() { return s_; }
   };
};

} // namespace MCSP

#endif // __INCLUDE_SESSION_H__
