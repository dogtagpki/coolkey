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

#include "machdep.h"
#include "mypkcs11.h"
#include "PKCS11Exception.h"
#ifdef _WIN32
#include <windows.h>
#include <memory.h>
#else
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#endif

bool OSLock::needThread = 0;

#ifdef _WIN32
//
// Windows functions to grab a named shared memory segment of a specific size,
// return whether or not it has been initialized, return it's size and address,
// release it when done.
//
struct SHMemData {
   char *addr;
   HANDLE map;
   int size;
   SHMemData() : addr(0), map(0), size(0) {}
};

SHMem::SHMem(): shmemData(0) {}

SHMem *
SHMem::initSegment(const char *name, int size, bool &init)
{
    bool needInit;
   
    init = 0;
    SHMemData *shmemData = new SHMemData;
    if (!shmemData ) {
	// applications know we failed because they will get a NULL address
	// from getSHMemAddr.
	return NULL;
    }

   shmemData->map = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
		 PAGE_READWRITE, 0, size, name);
   if (!shmemData->map) {
	delete shmemData;
	return NULL;
   }
   needInit = (GetLastError() != ERROR_ALREADY_EXISTS);

   shmemData->addr = 
	(char *)MapViewOfFile(shmemData->map, FILE_MAP_WRITE, 0, 0, 0 );
   if (!shmemData->addr) {
	CloseHandle(shmemData->map);
	delete shmemData;
	return NULL;
    }
    shmemData->size = size;
    init = needInit;
    SHMem *memseg;

    memseg = new SHMem();
    if (memseg) {
	memseg->shmemData = shmemData;
    }
    return memseg;
}

SHMem::~SHMem()
{
    if (!shmemData) {
	return;
    }
    if (shmemData->addr) {
	UnmapViewOfFile(shmemData->addr);
    }
    if (shmemData->map) {
	CloseHandle(shmemData->map);
    }
    delete shmemData;
}

char *
SHMem::getSHMemAddr()
{
    return shmemData ? shmemData->addr : NULL;
}

int
SHMem::getSHMemSize()
{
    return shmemData ? shmemData->size : 0;
}

struct OSLockData {
    CRITICAL_SECTION mutex;
};

OSLock::OSLock(bool exceptionAllowed)
{
    if (!needThread) {
	lockData = NULL;
	return;
    }
    lockData = new OSLockData;
    if (lockData) {
	InitializeCriticalSection(&lockData->mutex);
    } 
    if (exceptionAllowed && !lockData) {
	throw PKCS11Exception(CKR_HOST_MEMORY, "lock allocation failed");
    }
}

OSLock::~OSLock()
{
    if (lockData) {
	DeleteCriticalSection(&lockData->mutex);
	delete lockData;
    }
}

bool OSLock::isValid()
{
    return (bool) (lockData != NULL);
}

void OSLock::getLock()
{
    if (lockData) {
	EnterCriticalSection(&lockData->mutex);
    }
}

void OSLock::releaseLock()
{
    if (lockData) {
	LeaveCriticalSection(&lockData->mutex);
    }
}

OSTime OSTimeNow(void) 
{
    return GetTickCount(); 
}

void OSSleep(int time) 
{
    Sleep(time);
}

#else
//
// MAC/Unix functions to grab a named shared memory segment of a specific size,
// return whether or not it has been initialized, return it's size and address,
// release it when done.
//
#ifdef O_EXLOCK
#define FULL_CLEANUP
#else
/* if we can't lock on open, don't use locking for now */
#undef FULL_CLEANUP
#define O_EXLOCK 0
#endif

#ifndef MAP_INHERIT
#define MAP_INHERIT 0
#endif

#ifndef BASEPATH
#ifdef MAC
#define BASEPATH "/var"
#else
#define BASEPATH "/var/cache"
#endif
#endif

#ifdef FULL_CLEANUP
#define RESERVED_OFFSET 256
#define MEMSEGPATH BASEPATH"/coolkey-lock"
#else 
#define RESERVED_OFFSET 0
#define MEMSEGPATH BASEPATH"/coolkey"
#endif

struct SHMemData {
   char *path;
   char *addr;
   int fd;
   int size;
   SHMemData() : path(0), addr(0), fd(-1), size(0) {}
   ~SHMemData() ;
};

SHMemData::~SHMemData() { 
    if (addr) {
	/* memory adder implies the fd and path are valid as well */
#ifdef FULL_CLEANUP
	flock(fd,LOCK_EX);
	unsigned long ref = --(*(unsigned long *)addr); 
	flock(fd, LOCK_UN);
#endif
	munmap(addr,size+RESERVED_OFFSET);
    }
    if (fd > 0) {
	close(fd);
    }
    if (path) {
	delete [] path;
    }
}

/*
 * The cache directory is shared and accessible by anyone, make
 * sure the cache file we are opening is really a valid cache file.
 */
int safe_open(char *path, int flags, int mode, int size)
{
    struct stat buf;
    int fd, ret;

    fd = open (path, flags|O_NOFOLLOW, mode);

    if (fd < 0) {
	return fd;
    }

    ret = fstat(fd, &buf);
    if (ret < 0) {
	close (fd);
	return ret;
    }

    /* our cache files are pretty specific, make sure we are looking
     * at the correct one */

    /* first, we should own the file ourselves, don't open a file
     * that someone else wanted us to see. */
    if (buf.st_uid != getuid()) {
	close(fd);
	errno = EACCES;
	return -1;
    }

    /* next, there should only be one link in this file. Don't
     * use this code to trash another file */
    if (buf.st_nlink != 1) {
	close(fd);
	errno = EMLINK;
	return -1;
    }

    /* next, This better be a regular file */
    if (!S_ISREG(buf.st_mode)) {
	close(fd);
	errno = EACCES;
	return -1;
    }

    /* if the permissions don't match, something is wrong */
    if ((buf.st_mode & 03777) != mode) {
	close(fd);
	errno = EACCES;
	return -1;
    }

    /* finally the file should be the correct size. This 
     * check isn't so much to protect from an attack, as it is to
     * detect a corrupted cache file */
    if (buf.st_size != size) {
	close(fd);
	errno = EACCES;
	return -1;
    }

    /* OK, the file checked out, ok to continue */
    return fd;
}

SHMem::SHMem(): shmemData(0) {}

SHMem *
SHMem::initSegment(const char *name, int size, bool &init)
{
    bool needInit = true;
    /* big enough to hold a uid_t value in decimal */
    /* decimal digits = ceiling(log10(uid_t_max)); */
    /* log10(uid_t_max) = log256(uid_t_max)/log256(10); */
    /* log256(uid_t_max) = sizeof(uid_t); */
    /* log10(256) just greater than .41 */
    /* so decimal_digits = (sizeof(uid_t)*100 +40)/41 */
#define UID_DIGITS (((sizeof(uid_t)*100)+40)/41)
    char uid_str[UID_DIGITS+2]; /* 1 for '-', 1 for null */
   
    init = 0;
    SHMemData *shmemData = new SHMemData;
    if (!shmemData ) {
	// applications know we failed because they will get a NULL address
	// from getSHMemAddr.
	return NULL;
    }
    int mask = umask(0);
    int ret = mkdir (MEMSEGPATH, 01777);
    umask(mask);
    if ((ret == -1) && (errno != EEXIST)) {
	delete shmemData;
	return NULL;
    }
    /* 1 for the '/', one for the '-' and one for the null */
    shmemData->path = new char [sizeof(MEMSEGPATH)+strlen(name)+UID_DIGITS+3];
    if (shmemData->path == NULL) {
	delete shmemData;
	return NULL;
    }
    memcpy(shmemData->path,MEMSEGPATH, sizeof(MEMSEGPATH));
    shmemData->path[sizeof(MEMSEGPATH)-1] = '/';
    strcpy(&shmemData->path[sizeof(MEMSEGPATH)],name);

    sprintf(uid_str, "-%u",getuid());
    strcat(shmemData->path,uid_str);
    int mode = 0600;

    shmemData->fd = open(shmemData->path, 
		O_CREAT|O_RDWR|O_EXCL|O_APPEND|O_EXLOCK, mode);
    if (shmemData->fd >= 0) {
	char *buf;
	int len = size+RESERVED_OFFSET;
        int ret;

	buf = (char *)calloc(1,len);
	if (!buf) {
	    unlink(shmemData->path);
#ifdef FULL_CLEANUP
	    flock(shmemData->fd, LOCK_UN);
#endif
	    delete shmemData;
	    return NULL;
	}
	ret = write(shmemData->fd,buf,len);
        if (ret != len) {
	    unlink(shmemData->path);
#ifdef FULL_CLEANUP
	    flock(shmemData->fd, LOCK_UN);
#endif
	    delete shmemData;
	    return NULL;
	}
	free(buf);
    } else if (errno == EEXIST) {
	needInit = false;
	shmemData->fd = safe_open(shmemData->path,O_RDWR|O_EXLOCK, mode,
				  size+RESERVED_OFFSET);
    }
    if (shmemData->fd < 0) {
	delete shmemData;
	return NULL;
    }
    shmemData->addr = (char *) mmap(0, size+RESERVED_OFFSET, 
			PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED|MAP_INHERIT, 
							shmemData->fd, 0);
    if (shmemData->addr == NULL) {
	if (needInit) {
	    unlink(shmemData->path);
	}
#ifdef FULL_CLEANUP
	flock(shmemData->fd, LOCK_UN);
#endif
	delete shmemData;
	return NULL;
    }
    shmemData->size = size;
#ifdef FULL_CLEANUP
    (*(unsigned long *)shmemData->addr)++; 
    flock(shmemData->fd, LOCK_UN);
#endif
    init = needInit;
    SHMem *memseg;

    memseg = new SHMem();
    if (!memseg) {
	delete shmemData;
	return NULL;
    }
    memseg->shmemData = shmemData;
    return memseg;
}

SHMem::~SHMem()
{
    if (!shmemData) {
	return;
    }
    delete shmemData;
}

char *
SHMem::getSHMemAddr()
{
    return shmemData ? shmemData->addr+RESERVED_OFFSET : NULL;
}

int
SHMem::getSHMemSize()
{
    return shmemData ? shmemData->size : 0;
}

struct OSLockData {
    pthread_mutex_t mutex;
};

static pthread_mutexattr_t OSLock_attr = {0};
static int OSLock_attr_init = 0;

OSLock::OSLock(bool exceptionAllowed)
{
    int rc;

    lockData = NULL;
    if (!needThread) {
	return;
    }
#ifdef MAC
    if (!OSLock_attr_init) {
	rc = pthread_mutexattr_init(&OSLock_attr);
	if (rc < 0) {
	   if (exceptionAllowed) {
		throw PKCS11Exception(CKR_DEVICE_ERROR, "lock init failed");
	   } else {
		return;
	   }
	}
	OSLock_attr_init = 1;
    }
#endif
    lockData = new OSLockData;
    if (lockData) {
	rc = pthread_mutex_init(&lockData->mutex, &OSLock_attr);
	if (rc < 0) {
	    delete lockData;
	    lockData = NULL;
	}
    } 
    if (exceptionAllowed && !lockData) {
	throw PKCS11Exception(CKR_HOST_MEMORY, "lock allocation failed");
    }
}

OSLock::~OSLock()
{
    if (lockData) {
	pthread_mutex_destroy(&lockData->mutex);
	delete lockData;
    }
}

bool OSLock::isValid()
{
    return (bool) (lockData != NULL);
}

void OSLock::getLock()
{
    if (lockData) {
	pthread_mutex_lock(&lockData->mutex);
    }
}

void OSLock::releaseLock()
{
    if (lockData) {
	pthread_mutex_unlock(&lockData->mutex);
    }
}

#ifdef USE_CLOCK
OSTime OSTimeNow(void) 
{ 
  OSTime ostime;
  clock_t time;

#if CLOCKS_PER_SEC < 1000
  ostime = time * (1000/CLOCKS_PER_SEC);
#else
  ostime = time / (CLOCKS_PER_SEC/1000);
#endif
  return ostime;
}

#else
OSTime OSTimeNow(void) 
{ 
  OSTime ostime;
  struct timeval tv;

  gettimeofday(&tv, NULL);

  ostime = tv.tv_usec/1000 + tv.tv_sec*1000;

  return ostime;
}
#endif

void OSSleep(int time) 
{ 
    usleep(time); 
}
#endif /* _WINDOWS */


