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
/ File   :   BinStr.h
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#ifndef __INCLUDE_BINSTR_H__
#define __INCLUDE_BINSTR_H__

#include <vector>

namespace MCSP {

// Special tag used to identify binary strings that have been converted to
// ASCII hex.  This allows us to recognize them and turn them back to raw
// binary when needed.  This is used with the container name mapping to
// CKA_ID's.
static const char* PREFIX = "BINCODED:";
static const size_t PREFIXLEN = strlen(PREFIX);

class BinStr : public std::vector<BYTE>
{
public:
   BinStr()
      : std::vector<BYTE>() {}

   BinStr(size_type size)
      : std::vector<BYTE>(size) {}

   BinStr(const char* str)
      { *this = str; }

   BinStr(const std::string& str)
      { *this = str; }

   // Helper for the common case of returning a DWORD/CK_ULONG size
   unsigned long size() const
      { return static_cast<unsigned long>(std::vector<BYTE>::size()); }

   // If the string has non-printable characters then it is converted to a hex
   // string of the binary data prefixed with PREFIX: (see definition above),
   // otherwise it is left alone. 
   bool BinToHex()
   {
      iterator itr = begin();
      for (; itr != end(); itr++)
      {
         if (!isgraph(*itr) && *itr != ' ') 
            break;
      }

      if (itr == end())
         return false;

      // Need to convert string to ASCII hex
      BinStr temp;
      temp = PREFIX;
      temp.resize(size() * 2 + temp.size());

      size_type pos = PREFIXLEN;
      itr = begin();
      for (; itr != end(); itr++, pos += 2)
         sprintf((char*)&temp[pos], "%.2x", *itr);

      swap(temp);
      return true;
   }

   // If the string has been encoded to hex with PREFIX: then this converts it
   // back to raw binary, otherwise it is left alone.
   bool HexToBin()
   {
      if (size() < PREFIXLEN)
         return false;
      if (memcmp(&(*this)[0], PREFIX, PREFIXLEN) != 0)
         return false;

      BinStr::size_type newSize = size() - PREFIXLEN;
      if (newSize % 2)
         return false;

      newSize /= 2;
      BinStr temp(newSize);
      size_type pos_in = PREFIXLEN, pos_out = 0;

      for (; pos_in < size(); pos_in += 2, pos_out++)
         temp[pos_out] = BinFromHexChars(&(*this)[pos_in]);

      swap(temp);
      return true;
   }

   // Helper for the common case of setting a BinStr to a char string value.
   // Note that this DOES include the NULL at the end.
   // FIXME: resizing is wierd, what if the BinStr is longer than the assigned value?
   void operator =(const char* str)
   {
      if (size() < strlen(str) + 1)
         resize(strlen(str) + 1);
      strcpy((char*)&(*this)[(size_type)0], str);
   }

   void operator =(const std::string& str)
   {
      resize(str.size());
      memcpy((char*)&(*this)[(size_type)0], &str[0], size());
   }

   void assign(const BYTE* data, size_t len)
   {
      resize(len);
      memcpy(&(*this)[0], data, len);
   }

protected:
   static BYTE BinFromHexChars(const BYTE* hex)
   {
      char temp[3] = { hex[0], hex[1], 0 };
      return static_cast<BYTE>(strtoul(temp, 0, 16));
   } };

} // namespace MCSP

#endif // __INCLUDE_BINSTR_H__ 
