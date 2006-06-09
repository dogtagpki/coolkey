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

#include <Windows.h>
#include "cky_base.h"
#include "dynlink.h"


ckyShLibrary 
ckyShLibrary_open(const char *libname)
{
    HMODULE library;
    library = LoadLibrary(libname);

    return (ckyShLibrary) library;
}

CKYStatus 
ckyShLibrary_close(ckyShLibrary _lib)
{
    HMODULE library = (HMODULE) _lib;
    BOOL ret;

    if( library == NULL ) {
        return CKYSUCCESS;
    }

    ret = FreeLibrary(library);
    library = NULL;

    if (!ret) {
	return CKYLIBFAIL;
    }

    return CKYSUCCESS;
}

CKYStatus
ckyShLibrary_getAddress(const ckyShLibrary _lib, void **func, 
							const char *funcName)
{
    const HMODULE library = (const HMODULE) _lib;

    *func = (void *)GetProcAddress(library, funcName);
    if (*func == NULL) {
	return CKYLIBFAIL;
    }

    return CKYSUCCESS;
}
