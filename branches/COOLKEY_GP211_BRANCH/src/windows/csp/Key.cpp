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
/ File   :   Key.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "csp.h"
#include "Key.h"

namespace MCSP {

Key::Key()
   : algId_(0), sessionKey_(true), hPublicKey_(-1), hPrivateKey_(-1), hFakeSessionKey_(0)
{
   lock_ = ::CreateMutex(NULL, FALSE, NULL); 
}

Key::Key(bool sessionKey)
   : algId_(0), sessionKey_(sessionKey), hPublicKey_(-1), hPrivateKey_(-1), hFakeSessionKey_(0)
{
   lock_ = ::CreateMutex(NULL, FALSE, NULL); 
}

Key::~Key()
{
   ::CloseHandle(lock_);
}

} // namespace MCSP
