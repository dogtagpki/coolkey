# BEGIN LICENSE BLOCK
# Copyright (c) 1999-2002 David Corcoran <corcoran@linuxnet.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# Changes to this license can be made only by the copyright author with
# explicit written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Alternatively, the contents of this file may be used under the terms of
# the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
# case the provisions of the LGPL are applicable instead of those above. If
# you wish to allow use of your version of this file only under the terms
# of the LGPL, and not to allow others to use your version of this file
# under the terms of the BSD license, indicate your decision by deleting
# the provisions above and replace them with the notice and other
# provisions required by the LGPL. If you do not delete the provisions
# above, a recipient may use your version of this file under the terms of
# either the BSD license or the LGPL.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# END LICENSE BLOCK

CORE_DEPTH = ..

#############################################################################
# Locations of toolkits.
#

#
# The Javacard kit, version 2.2. Version 2.1 should also work.
# 
# The following need to be set in environment variables or in custom.mk.
# Examples :
#
#JAVACARD_KIT_DIR=c:/hack/java_card_kit-2_2


#
# The JDK. You need to use version 1.3.x; other versions aren't supported
# by the converter classes.
#
#JAVA_HOME=/cygdrive/c/jdk1.3.1_07/

#
# The top-level directory of Schlumberger's Cyberflex SDK.
#
#SLB_DIR=c:\Program Files\Schlumberger

#
# The top-level of the open platform toolkey
#
#OPEN_PLATFORM_DIR=C:/open_platform

-include custom.mk

ifdef SLB_DIR
# sub directory of Schlumberger's Cyberflex SDK.
SLB_JAVA_DIR=$(SLB_DIR)/Smart Cards and Terminals/Cyberflex Access Kits/v4/
endif

ifdef windir
SEP="\;"
else
SEP=":"
endif

#############################################################################
# Build Constants

#
# The Applet Identification Number.
#
AID=0x62:0x76:0x01:0xFF:0x00:0x00:0x00

#
# The Package Identification Number.
#
PID=0x62:0x76:0x01:0xFF:0x00:0x00

#
# The Java package to which the applet belongs.
#
PACKAGE=com.redhat.ckey.applet

#
# The unqualified name of the applet class.
#
APPLET_CLASS_NAME=CardEdge

#
# The directory into which output will be generated.
#
OUTPUT_DIR=output

#############################################################################
# Generated build variables.

PACKAGE_DIR=$(subst .,/,$(PACKAGE))

JAVA_SRC_FILES=$(wildcard src/$(PACKAGE_DIR)/*.java)

APPLET_QUALIFIED_CLASS_NAME=$(PACKAGE).$(APPLET_CLASS_NAME)

CONVERTER_OUTPUT_DIR=$(OUTPUT_DIR)/$(PACKAGE_DIR)/javacard

JAVAC=$(JAVA_HOME)/bin/javac
JAVA=$(JAVA_HOME)/bin/java

JAVA_SRC_FILENAMES=$(notdir $(JAVA_SRC_FILES))
JAVA_CLASS_FILES=$(patsubst %.java,$(OUTPUT_DIR)/$(PACKAGE_DIR)/%.class, $(JAVA_SRC_FILENAMES))


#############################################################################
# The ultimate output of the build is applet.ijc. This file is ready to
# be loaded onto a token.
all: $(CONVERTER_OUTPUT_DIR)/applet.ijc

clobber: clean

clean:
	touch $(JAVA_SRC_FILES)


#############################################################################
# The first step in the build is to compile the Java source files (*.java)
# into class files (*.class). These class files are regular Java class files;
# they aren't specially formatted for Javacard yet.

#
# The classpath needed to compile the Java source code.
#
BUILD_CLASSPATH="$(JAVACARD_KIT_DIR)/lib/javacardframework.jar$(SEP)$(JAVACARD_KIT_DIR)/lib/api.jar$(SEP)$(OPEN_PLATFORM_DIR)/jc211/bin/visaop20.jar"

#BUILD_CLASSPATH="$(JAVACARD_KIT_DIR)/lib/javacardframework.jar"
#
# build rule
#
$(JAVA_CLASS_FILES): $(JAVA_SRC_FILES)
	mkdir -p $(CONVERTER_OUTPUT_DIR)
	perl ./update_buildid.pl $(JAVA_SRC_FILES)
	$(JAVAC) -classpath ${BUILD_CLASSPATH} -d $(OUTPUT_DIR) $(JAVA_SRC_FILES)


#############################################################################
# The next step is to convert the regular Java class files into the Javacard
# format, using the converter program included with the Javacard Kit.
# The output from the converter is applet.cap, but the next step expects
# applet.jar, so we rename it.


#
# Classpath for the converter.
#
CONVERT_CLASSPATH="$(JAVACARD_KIT_DIR)/lib/converter.jar$(SEP)$(JAVACARD_KIT_DIR)/lib/offcardverifier.jar$(SEP)$(SLB_JAVA_DIR)/Classlibrary/jc_api_212.jar"

#
# Location of the .exp files, used for "linking" Javacard code.
#
EXPORT_PATH="$(SLB_JAVA_DIR)/Toolkit/PRGMaker/Export Files"

#
# build rule
#
$(CONVERTER_OUTPUT_DIR)/applet.jar: $(JAVA_CLASS_FILES)
	@if [ "$(JAVACARD_KIT_DIR)" = "" -o "$(JAVA_HOME)" = "" -o "$(SLB_JAVA_DIR)" = "" -o "$(OPEN_PLATFORM_DIR)" = "" ]; then \
	    echo "Not all necessary variables have been set."; \
	    echo "JAVACARD_KIT_DIR=$(JAVA_CARD_KIT_DIR)"; \
	    echo "JAVA_HOME=$(JAVA_HOME)"; \
	    echo "SLB_JAVA_DIR=$(SLB_JAVA_DIR)"; \
	    echo "OPEN_PLATFORM_DIR=$(OPEN_PLATFORM_DIR)"; \
	    exit 1; \
	fi 
	$(JAVA) -classpath ${CONVERT_CLASSPATH} com.sun.javacard.converter.Converter -classdir $(OUTPUT_DIR) -out EXP JCA CAP -exportpath $(EXPORT_PATH) -applet $(AID) $(APPLET_QUALIFIED_CLASS_NAME) -d $(OUTPUT_DIR) $(PACKAGE) $(PID) 1.0 
	mv $(CONVERTER_OUTPUT_DIR)/applet.cap $@ 


###############################################################################
# Finally, we must prepare the applet.jar file to be loaded onto a Schlumberger
# token. This means preparing it to be verified by the on-card verifier, using
# TrustedLogic's "CodeShield" technology. The Schlumberger SDK provides
# a 'makeijc' program to do this. The output is applet.ijc, which is ready to
# be loaded onto a token.

#
# Classpath for the IJC converter.
#
IJC_CLASSPATH="$(SLB_JAVA_DIR)/Toolkit/PRGMaker/makeijc.jar"

#
# build rule
#
$(CONVERTER_OUTPUT_DIR)/applet.ijc: $(CONVERTER_OUTPUT_DIR)/applet.jar
	$(JAVA) -classpath $(IJC_CLASSPATH) com.slb.javacard.jctools.ijc.MakeIJC -verbose -expFileDir $(EXPORT_PATH) -type onCardVerifier $(CONVERTER_OUTPUT_DIR)/applet.jar
	-@mkdir -p .libs
	cp $@ .libs/CardEdge.$(shell cat .buildid).ijc

export:

libs: all
