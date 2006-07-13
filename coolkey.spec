# BEGIN COPYRIGHT BLOCK
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
# END COPYRIGHT BLOCK

Name: coolkey
Version: 1.0.1
Release: 1
Summary: CoolKey PKCS #11 module
License: LGPL
URL: http://directory.fedora.redhat.com/wiki/CoolKey
Source: coolkey-%{version}.tar.gz
Group: System Environment/Libraries
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: pcsc-lite-devel
BuildRequires: zlib-devel
Requires: pcsc-lite 
Requires: ifd-egate
Requires: ccid
Provides: CoolKey Openkey
Obsoletes: CoolKey Openkey
ExcludeArch: s390 s390x   # 390 does not have libusb or smartCards

%description
Linux Driver support for the CoolKey and CAC products. 

%package devel
Summary: CoolKey Applet libraries
Group: System Environment/Libraries

%description devel
Linux Driver support to access the CoolKey applet.

%prep
%setup -q

%build
%configure --disable-dependency-tracking 
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
ln -s pkcs11/libcoolkeypk11.so $RPM_BUILD_ROOT/%{_libdir}
rm -f $RPM_BUILD_ROOT/%{_libdir}/pkcs11/libcoolkeypk11.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/pkcs11/libcoolkeypk11.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/libckyapplet.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/libckyapplet.la

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc ChangeLog LICENSE 
%{_libdir}/libcoolkeypk11.so
%{_libdir}/pkcs11/libcoolkeypk11.so
%{_libdir}/libckyapplet.so.1
%{_libdir}/libckyapplet.so.1.0.0

%files devel
%{_libdir}/libckyapplet.so
%{_libdir}/pkgconfig/libckyapplet.pc
%{_includedir}/*.h


%changelog
* Mon Jul 10 2006 Bob Relyea <rrelyea@redhat.com> - 1.0.1-1
- Don't require pthread library in coolkey

* Mon Jul 10 2006 Bob Relyea <rrelyea@redhat.com> - 1.0.0-2
- remove s390 from the build

* Mon Jun 5 2006 Bob Relyea <rrelyea@redhat.com> - 1.0.0-1
- Initial revision for fedora
