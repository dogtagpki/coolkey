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

# Process this file with automake to create Makefile.in

SUBDIRS = 
AM_CPP_FLAGS =
pkcs11dir = $(libdir)/pkcs11
pkcs11_LTLIBRARIES = libcoolkeypk11.la

libcoolkeypk11_la_SOURCES = \
	coolkey.cpp \
	dllmain.cpp \
	locking.cpp \
	log.cpp \
	machdep.cpp \
	object.cpp \
	PKCS11Exception.cpp \
	slot.cpp    \
	config.h \
	locking.h \
	log.h \
	machdep.h \
	mypkcs11.h \
	object.h \
	params.h \
	PKCS11Exception.h \
	pkcs11f.h \
	pkcs11.h \
	pkcs11n.h \
	pkcs11t.h \
	slot.h \
	$(NULL)

libcoolkeypk11_la_LDFLAGS = -module -avoid-version -export-symbols coolkeypk11.sym
libcoolkeypk11_la_CPPFLAGS = $(CPPFLAGS) -DNSS_HIDE_NONSTANDARD_OBJECTS=1 -I$(top_srcdir)/clib $(PCSC_CFLAGS)
libcoolkeypk11_la_DEPENDENCIES = coolkeypk11.sym
libcoolkeypk11_la_LIBADD = @LIBCKYAPPLET@ 


#
# sigh, libtool doesn't maintain Linux and Solaris versioning info in
# their .def file. So convert a very general, easy to work an any platform
# coreconf .def file to a simplistic but acceptable libtool .sym file
#
coolkeypk11.sym: coolkeypk11.def
	grep -v ';+' $< | grep -v ';-' | sed -e 's; DATA ;;' -e 's,;;,,' -e 's,;.*,,' > $@

clean-generic:
	rm -f coolkeypk11.sym



#MODULE = coolkeypk11
#REQUIRES = ckyapplet zlib
#USE_STATIC_RTL=1

#BASE_LIBRARY_NAME = coolkeypk11
#LIBRARY_NAME = $(BASE_LIBRARY_NAME)
#MAPFILE = $(OBJDIR)/coolkeypk11.def

#DEFINES += -DSHLIB_SUFFIX=\"$(DLL_SUFFIX)\" -DSHLIB_PREFIX=\"$(DLL_PREFIX)\" \
# -DPKCS11_LIB_NAME=\"$(notdir $(SHARED_LIBRARY))\"

#DEFINES += -DNSS_HIDE_NONSTANDARD_OBJECTS=1

#pcdir = $(libdir)/pkgconfig
#pc_DATA = libcoolkey.pc
