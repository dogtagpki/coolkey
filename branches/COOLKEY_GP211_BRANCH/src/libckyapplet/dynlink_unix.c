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

#include <dlfcn.h>
#include <unistd.h>
#if !defined(MAC) && !defined(HPUX)
#include <link.h>
#endif
#include <assert.h>

#include "cky_base.h"
#include "dynlink.h"

ckyShLibrary
ckyShLibrary_open(const char *libname)
{
    void *library;

    library = dlopen(libname, RTLD_LAZY);
    return library;
}

CKYStatus
ckyShLibrary_close(ckyShLibrary library)
{
    int rv;

    if (library == NULL) {
        return CKYSUCCESS;
    }

    rv = dlclose(library);
    if( rv != 0 ) {
	return CKYLIBFAIL;
    }
    return CKYSUCCESS;
}

CKYStatus
ckyShLibrary_getAddress(const ckyShLibrary library, void **func, 
							const char *funcName)
{
    assert(library);
    void* f = dlsym(library, funcName);
    if( f == NULL ) {
	return CKYLIBFAIL;
    }
    *func = f;
    return CKYSUCCESS;
}
