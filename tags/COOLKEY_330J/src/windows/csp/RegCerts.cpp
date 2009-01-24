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
/ File   :   RegCerts.cpp
/ Date   :   July 5, 2003
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include <stdio.h>
#include "csp.h"

int main(int argc, char* argv[])
{
   HCRYPTPROV hProv;

   if (argc < 2)
   {
      printf("usage: %s [CSP NAME]\n", argv[0]);
      exit(1);
   }

   if (!CryptAcquireContext(&hProv, NULL, argv[1], PROV_RSA_FULL, 0))
   { 
      printf("CryptAcquireContext failed (0x%X)\n", GetLastError()); 
      exit(1);
   }

   printf("Got context\n");

   BYTE name[4096];
   DWORD nameSize = sizeof(name);
   DWORD flags = CRYPT_FIRST;

   while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, name, &nameSize, flags))
   {
      printf("While\n");
      flags = 0;
      nameSize = sizeof(name);

      if (!CryptSetProvParam(hProv, PP_REGISTER_CERTIFICATE, name, 0))
         printf("Error registering container (0x%X): \"%s\"\n", GetLastError(), name);

      printf("Registered container: \"%s\"\n", name);
  }

   printf("Done\n");
   CryptReleaseContext(hProv, 0);

   return 0;
}
