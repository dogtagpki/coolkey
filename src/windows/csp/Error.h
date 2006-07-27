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
/ File   :   Error.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_ERROR_H__
#define __INCLUDE_ERROR_H__

#include <string>

namespace MCSP {

///////////////////////////////////////////////////////////////////////////////
// Error handling
///////////////////////////////////////////////////////////////////////////////
class Error
{
public:
   DWORD code_;
   int line_;
   std::string file_;
   std::string func_;
   std::string msg_;

public:
   Error(DWORD code, int line, const char* file, const char* func, const char* msg)
      : code_(code), line_(line), file_(file), func_(func), msg_(msg) {}

   void log()
   {
      LOG("Exception: 0x%X at %s:%d in %s() \"%s\"\n", 
         code_, file_.c_str(), line_, func_.c_str(), msg_.c_str());
   }
};

// Utility template so we can catch errors of a specific type
// Example: catch(ErrorT<NTE_NO_MEMORY>& e)
// Will catch a NTE_NO_MEMORY error
template<DWORD>
class ErrorT : public Error
{
public:
   ErrorT(DWORD code, int line, const char* file, const char* func, const char* msg)
      : Error(code, line, file, func, msg) {}
};

} // namespace MCSP

// Utility macros
#define Throw(x) throw ErrorT<x>(x,__LINE__,__FILE__,__FUNCTION__,"")
#define ThrowMsg(x,y) throw ErrorT<x>(x,__LINE__,__FILE__,__FUNCTION__,y)

#endif // __INCLUDE_ERROR_H__
