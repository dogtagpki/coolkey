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
/ File   :   State.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "csp.h"
#include "cspres.h"
#include "State.h"
#include <winscard.h>

using namespace std;

namespace MCSP {

State::State()
   : init_(false), logging_(false), logFilename_("C:\\CSPDEBUG.log"), slot_(0), keyGenHack_(false), pkcs11dllname_("PKCS11.dll"),
     p11_(CK_INVALID_HANDLE)
{
   lock_ = ::CreateMutex(NULL, FALSE, NULL); 

   HKEY hKey = NULL;

   if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\"PROVIDER_NAME),
                    0,
                    KEY_READ,
                    &hKey) == ERROR_SUCCESS)
   {
      DWORD value = 0;
      DWORD size = sizeof(value);
      
      if (RegQueryValueEx(hKey, TEXT("Logging"), 0, 0, (LPBYTE)&value, &size) == ERROR_SUCCESS)
      {
         if (value)
            logging(true);
      }

      size = 0;
      if (RegQueryValueEx(hKey, TEXT("LogFilename"), 0, 0, 0, &size) == ERROR_SUCCESS)
      {
         LOG("LogFilename size is: %u\n", size);
         std::string value;
         value.resize(size);

         if (RegQueryValueEx(hKey, TEXT("LogFilename"), 0, 0, (LPBYTE)&value[0], &size) == ERROR_SUCCESS)
         {
            // Remove trailing null
            value.resize(value.size() - 1);
            logFilename_ = value;
         }
         LOG("LogFilename value is: %s\n", &value[0]);
      }

      size = sizeof(value);
      if (RegQueryValueEx(hKey, TEXT("KeyGenHack"), 0, 0, (LPBYTE)&value, &size) == ERROR_SUCCESS)
      {
         if (value)
            keyGenHack(true);
      }

      if (RegQueryValueEx(hKey, TEXT("PKCS11Module"), 0, 0, 0, &size) == ERROR_SUCCESS)
      {
         LOG("PKCS11Module size is: %u\n", size);
         std::string value;
         value.resize(size);

         if (RegQueryValueEx(hKey, TEXT("PKCS11Module"), 0, 0, (LPBYTE)&value[0], &size) == ERROR_SUCCESS)
         {
            // Remove trailing null
            value.resize(value.size() - 1);
            pkcs11dllname_ = value;
         }
         LOG("PKCS11Module value is: %s\n", &value[0]);
      }

      RegCloseKey(hKey);
   }
}

State::~State()
{
   shutdown();
   ::CloseHandle(lock_);
}

bool State::sessionExists(Session* session)
{
   bool rv = false;

   lock();
   set<Session*>::iterator itr = sessions_.find(session);
   if (itr != sessions_.end())
      rv = true;

   unlock();
   return rv;
}

void State::removeSession(Session* session)
{
   lock();
   sessions_.erase(session); 
   delete session; 
   unlock();
}

Session* State::checkValidSession(HCRYPTPROV hProv)
{
   //LOG("Checking 0x%X as a valid session handle\n", hProv);

   if (!sessionExists(reinterpret_cast<Session*>(hProv)))
      Throw(NTE_BAD_UID);

   return reinterpret_cast<Session*>(hProv);
}

bool State::keyExists(Key* key)
{
   bool rv = false;

   lock();
   set<Key*>::iterator itr = keys_.find(key);
   if (itr != keys_.end())
      rv = true;

   unlock();
   return rv;
}

Key* State::checkValidKey(HCRYPTKEY hKey)
{
   //LOG("Checking 0x%X as a valid key handle\n", hKey);

   if (!keyExists(reinterpret_cast<Key*>(hKey)))
      Throw(NTE_BAD_UID);

   return reinterpret_cast<Key*>(hKey);
}

void State::login(Session* session)
{

   int pin_size;
   BinStr userPIN;
   userPIN.resize(256);
   if (!(pin_size = CSPDisplayPinDialog((char*)&userPIN[0], userPIN.size())))
      ThrowMsg(SCARD_W_CANCELLED_BY_USER, "PIN dialog cancelled");

   userPIN.resize(pin_size);

   CK_RV ck_rv = g_state.p11->C_Login(session->p11_, CKU_USER, 
                  (CK_UTF8CHAR*)&userPIN[0], (CK_ULONG)userPIN.size());

   if (ck_rv == CKR_OK)
   {
      if (p11_ != CK_INVALID_HANDLE)
      {
         LOG("Existing invalid session must be destroyed. \n");

         g_state.p11->C_CloseSession(p11_);
         p11_ = CK_INVALID_HANDLE;
      }
      ck_rv = g_state.p11->C_OpenSession(g_state.slot(), CKF_RW_SESSION | CKF_SERIAL_SESSION, 0, 0, &p11_);
   }

   if (ck_rv != CKR_OK)
   {
      DisplayError(session, "Error during PIN verification");
      Throw(NTE_FAIL);
   }
   else
      LOG("PIN Verification Successful\n");

}


bool State::shutdown()
{
   if (init())
   {
      lock();

      LOG("Shutting down CSP\n");
      
      { 
         set<Session*>::iterator itr = sessions_.begin();
         for (; itr != sessions_.end(); itr++)
            delete *itr;

         sessions_.clear();
      }

      {
         set<Key*>::iterator itr = keys_.begin();
         for (; itr != keys_.end(); itr++)
         {
            LOG("Destroying key: 0x%X\n", *itr);
            delete *itr;
         }

         keys_.clear();
      }

      if (p11_ != CK_INVALID_HANDLE)
      {
         p11->C_CloseSession(p11_);
         p11_ = CK_INVALID_HANDLE;
      }

      g_state.p11->C_Finalize(0);
      init(false);

      unlock();
   }

   return true;
}

bool State::initP11(const BinStr& reader_name0, DWORD dwFlags)
{
   bool rv = true;
   CK_RV ck_rv;
   CK_SLOT_ID slot = 0;
   BinStr reader_name = reader_name0; // We may need to modify the value
   bool silent = false;

   lock();

   if ((dwFlags & CRYPT_SILENT) || (dwFlags & CRYPT_VERIFYCONTEXT))
      silent = true;

   try
   {
      HMODULE p11lib = LoadLibrary(pkcs11dllname_.c_str());
      if (p11lib == NULL)
      {
         LOG("Failed to load PKCS11 library \"%s\"\n", pkcs11dllname_.c_str());
         SetLastError(NTE_FAIL);
         throw(false);
      }

      CK_RV (*getfunc)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
      getfunc = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList))GetProcAddress(p11lib, "C_GetFunctionList");
      if (getfunc == NULL)
      {
         LOG("Failed to find C_GetFunctionList\n");
         SetLastError(NTE_FAIL);
         throw(false);
      }

      CK_RV rv = getfunc(&p11);
      if (rv != CKR_OK)
      {
         LOG("Failed to get PKCS11 function list\n");
         SetLastError(NTE_FAIL);
         throw(false);
      }

      ck_rv = p11->C_Initialize(0); 

      LOG("C_Initialize: 0x%X\n", ck_rv);
      if (ck_rv != CKR_OK && ck_rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
      {
         LOG("C_Initialize() failed: 0x%X (%u)\n", ck_rv, ck_rv);
         SetLastError(NTE_FAIL);
         throw(false);
      }

      CK_ULONG ulSlotCount;
      if (p11->C_GetSlotList(FALSE, 0, &ulSlotCount) != CKR_OK)
      {
         LOG("C_GetSlotList() failed\n");
         SetLastError(NTE_FAIL);
         throw(false);
      }

      LOG("There are %d slots on this machine\n", ulSlotCount);

      if (ulSlotCount < 1)
      {
         LOG("No slots detected\n");
         SetLastError(NTE_FAIL);
         throw(false);
      }

      vector<CK_SLOT_ID> slotList(ulSlotCount);

      if (p11->C_GetSlotList(FALSE, &slotList[0], &ulSlotCount) != CKR_OK)
      {
         LOG("C_GetSlotList() failed (second call)\n");
         SetLastError(NTE_FAIL);
         throw(false);
      }

      CK_SLOT_INFO slotInfo;
      BinStr current_reader;
      vector<CK_SLOT_ID>::iterator itr;
      bool found_slot = false;

      // FIXME: Look for the specified reader or if not specified then
      //        the first reader with a card present.  Should probably
      //        search for first valid token and use MS smartcard select
      //        dialog.
      while (!found_slot)
      {
         LOG("Looking for a valid token\n");

         CK_ULONG token_count = 0;
         itr = slotList.begin();
         for (; itr != slotList.end(); itr++)
         {
            p11->C_GetSlotInfo(*itr, &slotInfo);

            CK_TOKEN_INFO tokenInfo;
            CK_RV ck_rv = p11->C_GetTokenInfo(*itr, &tokenInfo);

            // Chop off trailing spaces in P11 slot name
            current_reader.assign(slotInfo.slotDescription, sizeof(slotInfo.slotDescription));
            while (current_reader[current_reader.size()-1] == 0x20)
               current_reader.resize(current_reader.size() - 1);
            current_reader.push_back(0);

            LOG("Slot %d: %s (looking for reader: %s)\n", *itr, &current_reader[0], reader_name.empty() ? "" : (char*)&reader_name[0]);

            if (!(slotInfo.flags & CKF_TOKEN_PRESENT))
            {
               LOG("^^^^^ (No card present)\n");

               if (reader_name == current_reader)
                  break;
            }
            else
            {
               string infoString((char*)tokenInfo.label, sizeof(tokenInfo.label));
               LOG("^^^^^ (%s)\n", infoString.c_str());

               token_count++;

               if (reader_name.empty())
               {
                  // If multiple tokens, ask user
                  if (token_count > 1 && !silent)
                     break;

                  found_slot = true;
                  slot = *itr;
               }
               else if (reader_name == current_reader)
               {
                  found_slot = true;
                  slot = *itr;
                  break;
               }
            }
         }

         if (token_count > 1 && !silent)
         {
            SCARDCONTEXT hSC;
            OPENCARDNAME_EX dlgStruct;
            char szReader[256];
            char szCard[256];

            if (SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC) != SCARD_S_SUCCESS)
            {
               LOG("Failed SCardEstablishContext\n");
               SetLastError(NTE_FAIL);
               throw(false);
            }

            memset(&dlgStruct, 0, sizeof(dlgStruct));
            dlgStruct.dwStructSize = sizeof(dlgStruct);
            dlgStruct.hSCardContext = hSC;
            dlgStruct.dwFlags = SC_DLG_FORCE_UI;
            dlgStruct.lpstrRdr = szReader;
            dlgStruct.nMaxRdr = 256;
            dlgStruct.lpstrCard = szCard;
            dlgStruct.nMaxCard = 256;
            //dlgStruct.lpstrTitle = "Select Card:";

            // FIXME: Will this work during login?
            if (SCardUIDlgSelectCard(&dlgStruct) != SCARD_S_SUCCESS)
            {
               SCardReleaseContext(hSC);
               LOG("Failed SCardUIDlgSelectCard\n");
               SetLastError(NTE_FAIL);
               throw(false);
            }
            else
            {
               SCardReleaseContext(hSC);
               LOG("User selected reader: %s card: %s\n", szReader, szCard);
               reader_name = (char*)szReader;
               slot = 0;
               continue; // This will restart the search loop to find the selected reader
            }
         }

         if (!found_slot)
         {
            if (silent)
            {
               LOG("ERROR: Can't find a card in any reader and silent mode is set");
               SetLastError(NTE_FAIL);
               throw(false);
            }

            // FIXME: will this work during login?
            int result = MessageBox(NULL, "Please insert a supported smartcard",
               "Insert Card", MB_ICONEXCLAMATION | MB_RETRYCANCEL);

            if (result == IDCANCEL)
            {
               SetLastError(NTE_FAIL);
               throw(false);
            }
         }
      }

      LOG("Using slot %d\n", slot);

      g_state.slot(slot);
   }
   catch (bool rv0)
   {
      rv = rv0;
   }

   unlock();

   return rv;
}

} // namespace MCSP
