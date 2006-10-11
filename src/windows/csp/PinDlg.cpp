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

// PinDlg.cpp : implementation file
//

#include "stdafx.h"
#include "PinDlg.h"
#include "cspres.h"

static CPinDlg* g_PinDlg = 0;
static CWnd* g_CSPPinDialogParent = 0;

void CSPSetParentPinDialog(void* parent)
{
   g_CSPPinDialogParent = (CWnd*)parent;
}

int CSPDisplayPinDialog(char* pin, int max_len)
{
   AFX_MANAGE_STATE(AfxGetStaticModuleState());

   if (!pin)
      return 0;

   CString str_pin;
   int length = 0;
   CPinDlg dlg(g_CSPPinDialogParent);
   g_PinDlg = &dlg;
   INT_PTR rv = dlg.DoModal();
   if (rv == IDOK)
   {
      str_pin = dlg.m_PinValue;
      length = str_pin.GetLength();

      if (length <= max_len)
         memcpy(pin, (const char*)str_pin, length);
      else
         length = 0;
   }

   g_PinDlg = 0;

   g_CSPPinDialogParent = 0;

   return length;
}

void CSPCancelPinDialog()
{
   if (g_PinDlg)
      g_PinDlg->EndDialog(IDCANCEL);
}

// CPinDlg dialog

IMPLEMENT_DYNAMIC(CPinDlg, CDialog)
CPinDlg::CPinDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPinDlg::IDD, pParent)
{
}

CPinDlg::~CPinDlg()
{
}

BOOL CPinDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

   char base[_MAX_PATH];
   char fname[_MAX_FNAME];
   char ext[_MAX_EXT];

   GetModuleFileName(0, base, sizeof(base));
   _splitpath(base, NULL, NULL, fname, ext);
   //printf("%s%s\n", fname, ext);

   m_Pin.SetFocus();

   return FALSE;
}


void CPinDlg::DoDataExchange(CDataExchange* pDX)
{
   CDialog::DoDataExchange(pDX);
   DDX_Control(pDX, IDC_CSPRES_PIN, m_Pin);
   DDX_Control(pDX, IDOK, m_OKBtn);
}


BEGIN_MESSAGE_MAP(CPinDlg, CDialog)
   ON_BN_CLICKED(IDOK, OnBnClickedOk)
   ON_EN_CHANGE(IDC_CSPRES_PIN, OnEnChangePin)
END_MESSAGE_MAP()


// CPinDlg message handlers


void CPinDlg::OnBnClickedOk()
{
   // TODO: Add your control notification handler code here
   OnOK();
}

void CPinDlg::OnEnChangePin()
{
   // TODO:  If this is a RICHEDIT control, the control will not
   // send this notification unless you override the CDialog::OnInitDialog()
   // function and call CRichEditCtrl().SetEventMask()
   // with the ENM_CHANGE flag ORed into the mask.

   m_Pin.GetWindowText(m_PinValue);
   if (m_PinValue.GetLength() == 0)
      m_OKBtn.EnableWindow(0);
   else
      m_OKBtn.EnableWindow(1);
}
