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
/ File   :   uuid.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include <windows.h>
#include <rpcdce.h>

#include "BinStr.h"

namespace MCSP {

bool GenUUID(BinStr* uuid)
{
   uuid->clear();

   unsigned char* strId;
   UUID id;
   UuidCreate(&id);
   if (UuidToString(&id, &strId) == RPC_S_OK)
   {
      uuid->resize(strlen((char*)strId));
      memcpy(&(*uuid)[0], strId, strlen((char*)strId));
      RpcStringFree(&strId);
      return true;
   }
   else
      return false;
}

} // namespace MCSP
