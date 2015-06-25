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

#ifndef COOLKEY_LOCKING_H
#define COOLKEY_LOCKING_H

#include "mypkcs11.h"
#include <assert.h>

class Mutex {
  public:
    virtual ~Mutex() { }
    virtual void lock()=0;
    virtual void unlock()=0;
};

class MutexFactory {

  public:
    MutexFactory(const CK_C_INITIALIZE_ARGS* initArgs);
    ~MutexFactory();
    Mutex* createMutex() const;
    
  private:
    CK_C_INITIALIZE_ARGS *initArgs;
};

class Guardable;

class Guard {
  public:
    Guard(Mutex& mutex_) : mutex(&mutex_) { mutex->lock(); }
    Guard(Mutex* mutex_) : mutex(mutex_) { mutex->lock(); }
    Guard(Guardable& g);
    Guard(Guardable* g);
    ~Guard() { if( mutex ) mutex->unlock(); }

    Guard(Guard& g) {
        mutex = g.mutex;
        g.mutex = 0;
    }
    Guard& operator=(Guard&g) {
        mutex = g.mutex;
        g.mutex = 0;
        return *this;
    }

    void unlock() { if( mutex ) mutex->unlock(); mutex = 0; }
  private:
    Mutex* mutex;
};

class Guardable {
  private:
    friend class Guard;
    Mutex *mutex;
  public:
    Guardable(const MutexFactory* mutexFactory) {
        mutex = mutexFactory->createMutex();
    }
    ~Guardable() {
        delete mutex;
    }
};

inline
Guard::Guard(Guardable& g) {
    mutex = g.mutex;
    mutex->lock();
}

inline
Guard::Guard(Guardable* g) {
    mutex = g->mutex;
    mutex->lock();
}

#endif
