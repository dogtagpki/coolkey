#
# BEGIN COPYRIGHT BLOCK
# This Program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; version 2 of the License.
#
# This Program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307 USA.
#
# Copyright (C) 2006 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK 
#
#
# Nmake capable makefile.
#


# Deal with flags for the debug version.
# 
DBGLCFLAGS =
DBGFLAGS =
MTLIB = -MT

!IF "$(BUILD_OPT)" == "1"
DBGLCFLAGS = -ZI -DEBUG -D_DEBUG
DBGFLAGS = /DEBUG
MTLIB = -MTd
!ENDIF

# Deal with 32 or 64 bit machine.
#
ARCH = X86

!IF "$(USE_64)" == "1"
ARCH = X64
!ENDIF
 
LCFLAGS=-Od -I$(CAPISDK)/sdkinc -DWIN32  -D_WINDOWS -D_USRDLL    \
          -D_CONSOLE -DCSP_EXPORTS -D_WINDLL -DIDA_PROMPT_PINGUI -D_MBCS \
	   -EHsc -RTC1 -W3 -nologo -c $(DBGCLFLAGS) -TP

CSPRESFLAGS=/INCREMENTAL:NO /NOLOGO /DLL /DEF:"cspres.def" $(DBGFLAGS)    \
            /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /IMPLIB:"cspres.lib" \
            /MACHINE:$(ARCH)

CSPFLAGS=/INCREMENTAL:NO /NOLOGO /DLL /DEF:"csp.def" $(DBGFLAGS)          \
	 /SUBSYSTEM:WINDOWS /IMPLIB:"clkcsp.lib" /MACHINE:$(ARCH) crypt32.lib \
	 RpcRT4.Lib winscard.lib Scarddlg.lib cspres.lib  kernel32.lib    \
         user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib      \
         shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib 

REGCERTSFLAGS=/INCREMENTAL:NO /NOLOGO $(DBGFLAGS) /SUBSYSTEM:CONSOLE /MACHINE:$(ARCH) \
              kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib    \
              advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib       \
              odbc32.lib odbccp32.lib 
CC=cl

TARGETS=cspres.dll clkcsp.dll regcerts.exe clkcsp.sig
TRASH=*.pdb *.lib *.exp *.idb *.manifest

CSP_OBJ =  \
    csp.obj \
    cspx.obj \
    gui.obj \
    Key.obj \
    RegDll.obj \
    Session.obj \
    State.obj \
    uuid.obj \
    csp.res \
    $(NULL)

CSP_RES_OBJ = \
    cspres.OBJ \
    PinDlg.OBJ \
    cspres.res \
    $(NULL)

REG_CERTS_OBJ = \
    RegCerts.obj \
    $(NULL)

.SUFFIXES: .cpp .obj .OBJ .rc .res .Obj .dll .sig

.cpp.obj:
	$(CC) $(LCFLAGS) $(MTLIB) $<

.cpp.Obj:
	$(CC) $(LCFLAGS) -MLd -Wp64 $<

.cpp.OBJ:
	$(CC) $(LCFLAGS) -D_AFXDLL -MD $<

.dll.sig: 
	cmd /c "$(CAPISDK)/cspSign s $< $@"
	cmd /c "$(CAPISDK)/cspSign.exe v $< $@"

.rc.res:
	rc $(DEFINES) -D_AFXDLL $<

all:	$(TARGETS)

clean:
	rm -f $(TARGETS) $(CSP_OBJ) $(CSP_RES_OBJ) $(REG_CERTS_OBJ) $(TRASH)

cspres.dll: $(CSP_RES_OBJ)
	link  /OUT:cspres.dll $(CSP_RES_OBJ) $(CSPRESFLAGS)
#Process manifest file if applicable.
!IF "$(_NMAKE_VER)" >= "8.00" 
	mt.exe -manifest cspres.dll.manifest -outputresource:"cspres.dll;2"
!ENDIF
clkcsp.dll: $(CSP_OBJ) 
	link  /OUT:clkcsp.dll $(CSP_OBJ) $(CSPFLAGS)
!IF "$(_NMAKE_VER)" >= "8.00" 
	mt.exe -manifest clkcsp.dll.manifest -outputresource:"clkcsp.dll;2"
!ENDIF
regcerts.exe: $(REG_CERTS_OBJ)
	link  /OUT:regcerts.exe $(REG_CERTS_OBJ) $(REGCERTSFLAGS)
!IF "$(_NMAKE_VER)" >= "8.00"
	mt.exe -manifest regcerts.exe.manifest -outputresource:"regcerts.exe;1"
!ENDIF
