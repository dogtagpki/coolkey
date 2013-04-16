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

#include "mypkcs11.h"
#include <string>
#include <cstdarg>
#include <assert.h>
#include "log.h"
#include "PKCS11Exception.h"

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

PKCS11Exception::PKCS11Exception(CK_RV crv_, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    makeMessage(format, args);

    va_end(args);

    crv = crv_;
}
void
PKCS11Exception::log(Log *log) const
{
    log->log("Error 0x%08x: %s\n", crv, getMessageStr());
}

void
PKCS11Exception::makeMessage(const char *format, va_list args)
{
    char buf[BUFSIZE];
    vsnprintf(buf, BUFSIZE, format, args);
    message = string(buf);
}
