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

#pragma once
#include "afxwin.h"
#include "resource.h"

// CPinDlg dialog

class
CPinDlg : public CDialog
{
	DECLARE_DYNAMIC(CPinDlg)

public:
   CString m_PinValue;
	CPinDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPinDlg();

// Dialog Data
	enum { IDD = IDD_PIN_DIALOG };

protected:
   virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
   CEdit m_Pin;
   afx_msg void OnBnClickedOk();
   afx_msg void OnEnChangePin();
   CButton m_OKBtn;
};
