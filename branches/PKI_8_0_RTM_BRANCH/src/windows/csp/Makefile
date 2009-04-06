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
LCFLAGS=-Od -I$(CAPISDK)/sdkinc -DWIN32 -D_DEBUG -D_WINDOWS -D_USRDLL    \
          -D_CONSOLE -DCSP_EXPORTS -D_WINDLL -DIDA_PROMPT_PINGUI -D_MBCS \
	  -Gm -EHsc -RTC1 -W3 -nologo -c -ZI -TP

CSPRESFLAGS=/INCREMENTAL:NO /NOLOGO /DLL /DEF:"cspres.def" /DEBUG     \
            /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /IMPLIB:"cspres.lib" \
            /MACHINE:X86

CSPFLAGS=/INCREMENTAL:NO /NOLOGO /DLL /DEF:"csp.def" /DEBUG               \
	 /SUBSYSTEM:WINDOWS /IMPLIB:"clkcsp.lib" /MACHINE:X86 crypt32.lib \
	 RpcRT4.Lib winscard.lib Scarddlg.lib cspres.lib  kernel32.lib    \
         user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib      \
         shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib 

REGCERTSFLAGS=/INCREMENTAL:NO /NOLOGO /DEBUG /SUBSYSTEM:CONSOLE /MACHINE:X86 \
              kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib    \
              advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib       \
              odbc32.lib odbccp32.lib 
CC=cl

TARGETS=cspres.dll clkcsp.dll regcerts.exe clkcsp.sig
TRASH=*.pdb *.lib *.exp *.idb

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
	$(CC) $(LCFLAGS) -MTd $<

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

clkcsp.dll: $(CSP_OBJ) 
	link  /OUT:clkcsp.dll $(CSP_OBJ) $(CSPFLAGS)

regcerts.exe: $(REG_CERTS_OBJ)
	link  /OUT:regcerts.exe $(REG_CERTS_OBJ) $(REGCERTSFLAGS)

