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
 * ***** END COPYRIGHT BLOCK ***** */

/*
 * the following header file is private to the CoolKey library.
 * This is because CoolKey library is supposed to operate in the PKCS #11 
 * module which needs to be independent of runtimes like NSPR.  Longer term
 * there should be a generic version of this which uses the application
 * runtime, and pkcs #11 supplies it's only copy of these functions.
 */
#ifndef CKY_SHLIB_H
#define CKY_SHLIB_H  1

#undef QUOTE
#undef QUOTE_MACRO
#define QUOTE(arg) #arg
#define QUOTE_MACRO(arg) QUOTE(arg)

/* Hmmm maybe this should be hidden in getAddress? */
#ifdef MAC
#define DLL_SYM_PREFIX "_"
#else
#define DLL_SYM_PREFIX
#endif

#define MAKE_DLL_SYMBOL(name) DLL_SYM_PREFIX QUOTE(name)

typedef void *ckyShLibrary;

ckyShLibrary ckyShLibrary_open(const char *libname);
CKYStatus ckyShLibrary_close(ckyShLibrary libHandle);
CKYStatus ckyShLibrary_getAddress(ckyShLibrary libHandle, 
					void **func, const char *funcName);

#ifdef MAC
void ckyShLibrary_setParent(char *name);
#endif
#endif
