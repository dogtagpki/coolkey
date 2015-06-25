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

#ifndef COOLKEY_PKCS11EXCEPTION_H
#define COOLKEY_PKCS11EXCEPTION_H

#include "mypkcs11.h"
#include <string>
#include <cstdarg>
#include "log.h"

using std::string;

class PKCS11Exception {

  private:
    enum { BUFSIZE = 1024 };

    CK_RV crv;
    string message;

    void makeMessage(const char *format, va_list args);

  public:
    PKCS11Exception(CK_RV crv_) : crv(crv_) { }
    PKCS11Exception(CK_RV crv_, string message_)
        : crv(crv_), message(message_)  { }
    PKCS11Exception(CK_RV crv_, const char *format, ...);

    CK_RV getReturnValue() const {
        return crv;
    }

    CK_RV getCRV() const {
        return crv;
    }

    string getMessage() const {
        return message;
    }

    const char *getMessageStr() const { return message.c_str(); }

    void log(Log *l) const;

};

#endif
