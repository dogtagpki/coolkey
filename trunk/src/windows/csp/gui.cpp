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
/ File   :   gui.cpp
/ Date   :   December 3, 2002
/ Purpose:   Crypto API CSP->PKCS#11 Module
/ License:   Copyright (C) 2003-2004 Identity Alliance
/
******************************************************************/

#include "resource.h"
#include "csp.h"
#include <tchar.h>

using namespace std;

namespace MCSP {

static BOOL DoInitDialog(HWND hDlg, LPARAM lParam)
{
   RECT rect;
   int width, height;
   int screen_x, screen_y;
   int x, y;

   GetWindowRect(hDlg, &rect);
   width = rect.right - rect.left;
   height = rect.bottom - rect.top;

   screen_x = GetSystemMetrics(SM_CXSCREEN);
   screen_y = GetSystemMetrics(SM_CYSCREEN);

   x = screen_x/2 - width/2;
   y = screen_y/2 - height/2;

   SetWindowPos(hDlg, HWND_TOPMOST, x, y, width, height, SWP_NOSIZE);
   SetFocus(GetDlgItem(hDlg, IDC_PIN_EDIT));

   if (lParam == 0)
   {
      SetLastError(ERROR_INVALID_BLOCK);
      EndDialog(hDlg, 0);
      return TRUE;
   }

   // FIXME: Why does lParam need to be type-cast to LONG?
   //        The parameter is suppose to be LONG_PTR (LPARAM)
   SetWindowLongPtr(hDlg, GWLP_USERDATA, static_cast<LONG>(lParam));
   EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

   return FALSE;
}

static BOOL DoPINChanged(HWND hDlg)
{
   HWND pinCtrl;
   BOOL enable = TRUE;

   pinCtrl = GetDlgItem(hDlg, IDC_PIN_EDIT);
   int len = GetWindowTextLength(pinCtrl);

   if (len == 0)
      enable = FALSE;

   EnableWindow(GetDlgItem(hDlg, IDOK), enable);

   return TRUE;
}

static BOOL DoPIN(HWND hDlg, WPARAM wParam)
{
   switch(HIWORD(wParam))
   {
   case EN_UPDATE:
      return DoPINChanged(hDlg);
      break;
   default:
      break;
   }

   return TRUE;
}

static void OnOK(HWND hDlg, LPARAM lParam)
{
   BinStr* s = reinterpret_cast<BinStr*>((LPARAM)GetWindowLongPtr(hDlg, GWLP_USERDATA));
   if (!s)
      return;

   HWND pinCtrl = GetDlgItem(hDlg, IDC_PIN_EDIT);
   int len = GetWindowTextLength(pinCtrl);

   s->resize(len + 1);
   GetWindowText(pinCtrl, reinterpret_cast<LPSTR>(&(*s)[0]), static_cast<int>(s->size()));
   
   // Chop off null cause we don't need it
   s->resize(s->size() - 1);

   EndDialog(hDlg, IDOK);
}

static BOOL DoCommand(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
   switch(LOWORD(wParam))
   {
   case IDCANCEL:
      EndDialog(hDlg, IDCANCEL);
      break;
   case IDOK:
      OnOK(hDlg, lParam);
      break;
   case IDC_PIN_EDIT:
      return DoPIN(hDlg, wParam);
      break;
   default:
      break;
   }

   return TRUE;
}

static
INT_PTR CALLBACK PINDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
   switch (message)
   {
   case WM_COMMAND:
      return DoCommand(hDlg, wParam, lParam);
      break;
   case WM_INITDIALOG:
      return DoInitDialog(hDlg, lParam);
      break;
   default:
      break;
   }

   return FALSE;
}

// asks the user for a pin
bool DisplayPINDialog(BinStr* pin)
{
   INT_PTR result;

   result = DialogBoxParam(g_hModule, MAKEINTRESOURCE(IDD_PIN_DIALOG), NULL,
      PINDialogProc, reinterpret_cast<LPARAM>(pin));

   switch(result)
   {
   case 0:
      return false;
      break;
   case IDCANCEL:
      return false;
      break;
   case IDOK:
      if (pin->empty())
         return false;
      else
         return true;
      break;
   default:
      break;
   }

   return false;
}

// for debugging
void DisplayError(const Session* context, const string& str)
{
   if (!context->silent_)
      MessageBox(NULL, str.c_str(), PROVIDER_NAME" Error", MB_OK | MB_ICONERROR | MB_TASKMODAL);

   LOG("ERROR: \"%s\"\n", str.c_str());
}

// for debugging
void DisplayWin32Error(const Session* context)
{
   LPVOID lpMsgBuf;
   
   FormatMessage( 
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
      (LPTSTR) &lpMsgBuf,
      0,
      NULL 
      );
   
   // Display the string
   if (!context->silent_)
      MessageBox(NULL, (LPCSTR)lpMsgBuf, PROVIDER_NAME" Win32 Error", MB_OK | MB_ICONERROR | MB_TASKMODAL);

   LOG("WIN32 error: \"%s\"\n", lpMsgBuf);
   
   // Free the buffer.
   LocalFree( lpMsgBuf );
}

} // namespace MCSP
