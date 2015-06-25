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
 ***** END COPYRIGHT BLOCK *****/

#include <mach-o/dyld.h>
#include <stdio.h>
#include "cky_base.h"
#include "dynlink.h"
#include "string.h"
#include "stdlib.h"

#define EXEPATH "@executable_path/"
#define SYSPATH "/System/Library/Frameworks/"

static char *ckyShLibrary_parent = NULL;

/* allow the parent library to set our name */
void
ckyShLibrary_setParent(char *p)
{
    ckyShLibrary_parent = p;
}

#ifdef nodef
/* get the parent librarie's path */
char *
ckyShLibrary_getParentPath()
{
    char *result;
    char *image_name;
    int i, count = _dyld_image_count();

    if (ckyShLibrary_parent == NULL) {
	return NULL;
    }

    for (i = 0; i < count; i++) {
        image_name = _dyld_get_image_name(i); 
        if (strstr(image_name, ckyShLibrary_parent) != NULL) {
            result = malloc(strlen(image_name)+1);
            if (result != NULL) {
		char *truncate;
                strcpy(result, image_name);
		truncate = strrchr(result,'/');
		if (truncate) {
		    *(truncate+1) = 0;
		}
            }
            return result;
        }
    }
    return NULL;
}
#endif

ckyShLibrary
ckyShLibrary_open(const char *libname)
{
    const struct mach_header *library;
    /*char *parentPath = ckyShLibrary_getParentPath(); */
    char *libPath = NULL;
    int len = sizeof(SYSPATH);

#ifdef notdef
    if (parentPath) {
	int pLen = strlen(parentPath)+1;
	if (pLen > len) {
	   len = pLen;
	}
    }
#endif

    libPath = malloc(len+strlen(libname)+1);
    /* if we couldn't get the space, just use the LD_LIBPATH */
    if (libPath) {
#ifdef notdef
	/* first try the parent DLL path if known */
	if (parentPath) {
	    /* then try the path of the shared library */
	    strcpy(libPath,parentPath);
	    strcat(libPath,libname);
	    free(parentPath);
	    library = NSAddImage(libPath,
                         NSADDIMAGE_OPTION_RETURN_ON_ERROR |
                         NSADDIMAGE_OPTION_WITH_SEARCHING);
	    if (library) {
		free(libPath);
		return (ckyShLibrary)library;
	    }
	}
#endif
	/* the try the executable's lib path */
	strcpy(libPath,SYSPATH);
	strcat(libPath,libname);
	library = NSAddImage(libPath,
                         NSADDIMAGE_OPTION_RETURN_ON_ERROR |
                         NSADDIMAGE_OPTION_WITH_SEARCHING);
	free(libPath);
	if (library) {
	    return (ckyShLibrary)library;
	}
    }
	
    /* finally grab it from the system libpath */
    library = NSAddImage(libname,
                         NSADDIMAGE_OPTION_RETURN_ON_ERROR |
                         NSADDIMAGE_OPTION_WITH_SEARCHING);
    return (ckyShLibrary)library;
}

CKYStatus
ckyShLibrary_close(ckyShLibrary _lib)
{
    // Can't unload an image on Mac OS X.
    return CKYSUCCESS;
}

CKYStatus
ckyShLibrary_getAddress(const ckyShLibrary _lib, void ** func, 
							const char *funcName) 
{
    const struct mach_header *library = (const struct mach_header *)_lib;
    NSSymbol symbol;
    symbol = NSLookupSymbolInImage(library, funcName,
             NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
             NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
    if( symbol == NULL ) {
	return CKYLIBFAIL;
    }
    *func = NSAddressOfSymbol(symbol);
    return CKYSUCCESS;
}
