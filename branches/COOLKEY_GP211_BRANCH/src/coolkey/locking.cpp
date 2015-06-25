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

#include <assert.h>
#include "mypkcs11.h"
#include <string>
#include "locking.h"
#include "log.h"
#include "PKCS11Exception.h"

class BasicMutex : public Mutex {
  public:
    BasicMutex(CK_C_INITIALIZE_ARGS *initArgs);
    virtual ~BasicMutex();

    virtual void lock();
    virtual void unlock();

  private:
    void *mutex;
    CK_C_INITIALIZE_ARGS *initArgs;
};

class DummyMutex : public Mutex {
  public:
    virtual ~DummyMutex() { }
    virtual void lock() { }
    virtual void unlock() { }
};

BasicMutex::BasicMutex(CK_C_INITIALIZE_ARGS *initArgs_)
    : initArgs(initArgs_)
{
    assert( initArgs->CreateMutex != NULL );
    assert( initArgs->DestroyMutex != NULL );
    assert( initArgs->LockMutex != NULL );
    assert( initArgs->UnlockMutex != NULL );

    CK_RV crv = initArgs->CreateMutex(&mutex);

    if( crv != CKR_OK ) {
        throw PKCS11Exception(crv, "CreateMutex");
    }
}

BasicMutex::~BasicMutex()
{
    CK_RV crv = initArgs->DestroyMutex(mutex);

    if( crv != CKR_OK ) {
        throw PKCS11Exception(crv, "DestroyMutex");
    }
}

void
BasicMutex::lock()
{
    CK_RV crv = initArgs->LockMutex(mutex);

    assert(crv != CKR_MUTEX_BAD);
    if( crv != CKR_OK ) {
        throw PKCS11Exception(crv, "LockMutex");
    }
}

void
BasicMutex::unlock()
{
    CK_RV crv = initArgs->UnlockMutex(mutex);

    assert(crv != CKR_MUTEX_BAD);
    assert(crv != CKR_MUTEX_NOT_LOCKED);
    if( crv != CKR_OK ) {
        throw PKCS11Exception(crv, "UnlockMutex");
    }
}

MutexFactory::MutexFactory(const CK_C_INITIALIZE_ARGS* initArgs_)
    : initArgs(NULL)
{
    if( initArgs_ != NULL ) {
        if( initArgs_->CreateMutex == NULL || initArgs_->DestroyMutex == NULL
            || initArgs_->LockMutex == NULL || initArgs_->UnlockMutex == NULL )
        {
            if( initArgs_->flags & CKF_OS_LOCKING_OK ) {
                // application wants us to lock with OS primitives, which
                // we can't do
                throw PKCS11Exception(CKR_CANT_LOCK,
                    "Library cannot use OS locking primitives");
            } else {
                // Application is single threaded, so we won't do any
                // locking. Leave initArgs == NULL.
            }
        } else {
            // use the provided primitives for locking
            initArgs = new CK_C_INITIALIZE_ARGS(*initArgs_);
        }
    }
}

MutexFactory::~MutexFactory()
{
    if( initArgs != NULL ) {
        delete initArgs;
    }
}

Mutex*
MutexFactory::createMutex() const
{
    if( initArgs == NULL ) {
        return new DummyMutex();
    } else {
        return new BasicMutex(initArgs);
    }
}

