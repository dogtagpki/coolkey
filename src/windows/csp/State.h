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
/ File   :   State.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_STATE_H__
#define __INCLUDE_STATE_H__

#include "csp.h"

namespace MCSP {

// Global state; only one instance of this
class State
{
private:
   HANDLE lock_;
   bool init_;
   bool logging_;
   std::string logFilename_;
   CK_SLOT_ID slot_;
   bool keyGenHack_;
   std::set<Session*> sessions_;
   std::set<Key*> keys_;
   std::string pkcs11dllname_;

public:
   CK_FUNCTION_LIST_PTR p11;

public:
   State();
   ~State();

   bool init() const
      { return init_; }

   void init(bool init)
      { init_ = init; }

   bool logging() const
      { return logging_; }

   void logging(bool logging)
      { logging_ = logging; }

   std::string logFilename() const
      { return logFilename_; }

   void logFilename(std::string logFilename)
      { logFilename_ = logFilename; }

   CK_SLOT_ID slot() const
      { return slot_; }

   void slot(CK_SLOT_ID slot)
      { slot_ = slot; }

   bool keyGenHack() const
      { return keyGenHack_; }

   void keyGenHack(bool keyGenHack)
      { keyGenHack_ = keyGenHack; }

   void addSession(Session* session)
      { lock(); sessions_.insert(session); unlock(); }

   void removeSession(Session* session);
   bool sessionExists(Session* session);

   Session* checkValidSession(HCRYPTPROV hProv);

   void addKey(Key* key)
      { lock(); keys_.insert(key); unlock(); }

   void removeKey(Key* key)
      { lock(); keys_.erase(key); unlock(); }

   bool keyExists(Key* key);
   Key* checkValidKey(HCRYPTKEY hKey);
   bool shutdown();

   void lock()
      { ::WaitForSingleObject(lock_, INFINITE); }

   void unlock()
      { ::ReleaseMutex(lock_); }

   bool initP11(const BinStr& reader_name, DWORD dwFlags);
};

} // namespace MCSP
#endif // __INCLUDE_STATE_H__
