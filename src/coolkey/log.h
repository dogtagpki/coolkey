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

#ifndef COOLKEY_LOG_H
#define COOLKEY_LOG_H

#include <string>
#include <stdio.h>
#include <cky_base.h>

class Log {
  public:
    virtual void log(const char *msg, ...) = 0;
    virtual void dump(CKYBuffer *buf);
    virtual ~Log() { }
};

class DummyLog : public Log {
  public:
    DummyLog() { }
    void log(const char *msg, ...) { }
    void dump(CKYBuffer *buf) {}
    ~DummyLog() { }
};

class FileLog : public Log {
  private:
    FILE *file;

    // not allowed
    FileLog(FileLog &) { }
    FileLog& operator=(FileLog&) { return *this; }

  public:
    FileLog(const char *filename);
    void log(const char *msg, ...);
    virtual ~FileLog();
};

class SysLog : public Log {
  private:
   SysLog(SysLog &) {}
   SysLog & operator=(SysLog &) { return *this; }
  public:
    SysLog() {}
    void log(const char *msg, ...);
    virtual ~SysLog() {}
};

#endif
