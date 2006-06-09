# ***** BEGIN COPYRIGHT BLOCK *****
# Copyright (C) 2005 Red Hat, Inc.
# All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation version
# 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# ***** END COPYRIGHT BLOCK *****

LIB_RTL_SUFFIX=
ifeq (,$(filter-out WIN%,$(OS_TARGET)))
ifdef USE_STATIC_RTL
LIB_RTL_SUFFIX=_srtl
endif
endif

EXTRA_LIBS += \
	$(DIST)/lib/$(LIB_PREFIX)ckyapplet$(LIB_RTL_SUFFIX).$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)zlib$(LIB_RTL_SUFFIX).$(LIB_SUFFIX) \
	$(NULL)

# can't do this in manifest.mn because OS_TARGET isn't defined there.
ifeq (,$(filter-out WIN%,$(OS_TARGET)))

# don't want the 32 in the shared library name
SHARED_LIBRARY = $(OBJDIR)/$(DLL_PREFIX)$(LIBRARY_NAME)$(LIBRARY_VERSION).$(DLL_SUFFIX)
IMPORT_LIBRARY = $(OBJDIR)/$(IMPORT_LIB_PREFIX)$(LIBRARY_NAME)$(LIBRARY_VERSION)$(IMPORT_LIB_SUFFIX)

RES = $(OBJDIR)/$(LIBRARY_NAME).res
RESNAME = $(LIBRARY_NAME).rc

ifdef NS_USE_GCC
EXTRA_SHARED_LIBS += \
	-L$(DIST)/lib \
	$(NULL)
else # ! NS_USE_GCC

EXTRA_SHARED_LIBS += \
	$(NULL)
endif # NS_USE_GCC

else

# $(PROGRAM) has NO explicit dependencies on $(EXTRA_SHARED_LIBS)
# $(EXTRA_SHARED_LIBS) come before $(OS_LIBS), except on AIX.
EXTRA_SHARED_LIBS += \
	-L$(DIST)/lib/ \
	$(NULL)
endif

ifeq ($(OS_TARGET),SunOS)
ifndef USE_64
ifeq ($(CPU_ARCH),sparc)
# The -R '$ORIGIN' linker option instructs libsoftokn3.so to search for its
# dependencies (libfreebl_*.so) in the same directory where it resides.
MKSHLIB += -R '$$ORIGIN'
endif
endif
endif

ifeq ($(OS_TARGET),WINCE)
DEFINES += -DDBM_USING_NSPR
endif

ifeq ($(OS_TARGET),Linux)
CC=g++
EXTRA_SHARED_LIBS += -ldl -lpthread
#ifdef USE_STATIC_RTL
#MKSHLIB += -static-libgcc
#endif
endif
