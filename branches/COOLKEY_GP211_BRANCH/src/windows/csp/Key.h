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
/ File   :   Key.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_CSPKEY_H__
#define __INCLUDE_CSPKEY_H__

#include "csp.h"

namespace MCSP {

class Key
{
private:
   HANDLE lock_;

public:
   // FIXME: make these private and add accessors...
   ALG_ID algId_;
   bool sessionKey_;
   CK_OBJECT_HANDLE hPublicKey_;
   CK_OBJECT_HANDLE hPrivateKey_;
   HCRYPTKEY hFakeSessionKey_;

   Key();
   Key(bool sessionKey);
   ~Key();

   void lock()
      { ::WaitForSingleObject(lock_, INFINITE); }

   void unlock()
      { ::ReleaseMutex(lock_); }

   // Little helper that performs automatic thread locking (see csp.cpp for usage)
   class Ptr
   {
   private:
      Key *k_;
   public:
      Ptr(Key* k) { k_ = k; k_->lock(); }
      ~Ptr() { k_->unlock(); }
      Key* operator ->() { return k_; }
      operator Key*() { return k_; }
   };
};

} // namespace MCSP

#endif // __INCLUDE_CSPKEY_H__

