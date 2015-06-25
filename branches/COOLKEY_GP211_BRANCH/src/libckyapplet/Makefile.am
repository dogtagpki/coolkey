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

AM_CFLAGS =

EXTRA_DIST = \
	cky_list.i \
	dynlink_win.c \
	dynlink_unix.c \
	dynlink_mac.c

# bleh what do I add just to get static but pic libraries?
bogusdir = $(libdir)/bogus
lib_LTLIBRARIES = libckyapplet.la

libckyapplet_la_SOURCES = \
	cky_applet.c \
	cky_base.c \
	cky_card.c \
	cky_factory.c \
	dynlink.c 

quote=\"

libckyapplet_la_LDFLAGS = -version-info 1:0:0 -no-undefined
libckyapplet_la_CFLAGS = $(CFLAGS) -DSCARD_LIB_NAME=$(quote)$(SCARD_LIB_NAME)$(quote) $(PCSC_CFLAGS)

nobase_include_HEADERS = \
	cky_base.h \
	cky_card.h \
	cky_factory.h \
	cky_list.h \
	cky_applet.h 

noinst_HEADERS = \
	cky_basei.h \
	dynlink.h 

# remove the static and libtool libraries 
install-data-hook:
	rm -f $(DESTDIR)$(libdir)/libckyapplet.a
	rm -f $(DESTDIR)$(libdir)/libckyapplet.la
if IS_WINDOWS
	rm -f $(DESTDIR)$(libdir)/libckyapplet.lib
endif

if !IS_WINDOWS
pcdir = $(libdir)/pkgconfig
pc_DATA = libckyapplet.pc
endif
