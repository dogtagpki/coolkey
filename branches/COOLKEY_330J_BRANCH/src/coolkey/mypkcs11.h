/* ***** BEGIN COPYRIGHT BLOCK *****
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * ***** END COPYRIGHT BLOCK *****/

#ifndef COOLKEY_MYPKCS11_H
#define COOLKEY_MYPKCS11_H

#if defined(_WIN32)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv,func) rv __declspec(dllexport) func
#define CK_DECLARE_FUNCTION_POINTER(rv,func) rv (* func)
#define CK_CALLBACK_FUNCTION(rv,func) rv (* func)
#define CK_NULL_PTR 0
#else
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv,func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv,func) rv (* func)
#define CK_CALLBACK_FUNCTION(rv,func) rv (* func)
#define CK_NULL_PTR 0
#endif

#if defined(_WIN32)
#pragma warning(disable:4103)
#pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"

#include "pkcs11n.h"

#if defined (_WIN32)
#pragma warning(disable:4103)
#pragma pack(pop, cryptoki)
#endif


#endif
