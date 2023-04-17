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


#
#Substantial modifications to this Makefile were made by Aaron Curley.
#The modifications are licensed under the same provisions listed above.
#


#############################################################################
# Build Constants
#############################################################################

# The Applet Identification Number.
AID=0x62:0x76:0x01:0xFF:0x00:0x00:0x00

# The Package Identification Number.
PID=0x62:0x76:0x01:0xFF:0x00:0x00

# The Java package to which the applet belongs.
PACKAGE=com.redhat.ckey.applet

# The unqualified name of the applet class.
APPLET_CLASS_NAME=CardEdge

# The version of the package
MAJOR_VERSION=2
MINOR_VERSION=0

# The directory into which output will be generated.
OUTPUT_DIR=output

# Extra flags for the java compiler
JAVAC_FLAGS=-g -source 1.2 -target 1.2

# Extra flags for the class-to-CAP converter 
CONVERTER_FLAGS=-verbose

# Extra flags for CAP verifier
VERIFIER_FLAGS=-verbose

#############################################################################



#############################################################################
# Generated build variables.
#############################################################################

PACKAGE_DIR=$(subst .,/,$(PACKAGE))

JAVA_SRC_FILES=$(wildcard src/$(PACKAGE_DIR)/*.java)

APPLET_QUALIFIED_CLASS_NAME=$(PACKAGE).$(APPLET_CLASS_NAME)

CONVERTER_OUTPUT_DIR=$(OUTPUT_DIR)/$(PACKAGE_DIR)/javacard

JAVAC="$(JAVA_HOME)/bin/javac"
JAVA="$(JAVA_HOME)/bin/java"

JAVA_SRC_FILENAMES=$(notdir $(JAVA_SRC_FILES))
JAVA_CLASS_FILES=$(patsubst %.java,$(OUTPUT_DIR)/$(PACKAGE_DIR)/%.class, $(JAVA_SRC_FILENAMES))

#############################################################################



#############################################################################
# The ultimate output of the build is applet.cap
#############################################################################

all: check-env $(CONVERTER_OUTPUT_DIR)/applet.cap verifycapfile

check-env:
ifndef JAVA_HOME
	$(error JAVA_HOME is undefined)
endif
ifndef JC_HOME
	$(error JC_HOME is undefined)
endif
ifndef GP_HOME
	$(error GP_HOME is undefined)
endif

clean:
	rm -rf $(OUTPUT_DIR)
	rm -rf .libs

#############################################################################



############################################################################
# Rule to build .class files from .java source
#############################################################################

BUILD_CLASSPATH="${JC_HOME}/lib/api.jar:${GP_HOME}"

# build rule
$(JAVA_CLASS_FILES): $(JAVA_SRC_FILES)
	mkdir -p $(CONVERTER_OUTPUT_DIR)
	#perl ./update_buildid.pl $(JAVA_SRC_FILES)
	$(JAVAC) $(JAVAC_FLAGS) -classpath ${BUILD_CLASSPATH} -d $(OUTPUT_DIR) $(JAVA_SRC_FILES)

#############################################################################



#############################################################################
# Convert to .cap file from .class files
#############################################################################

# Location of the .exp files, used for "linking" Javacard code.
EXPORT_PATH="$(JC_HOME)/api_export_files:$(GP_HOME)"

# UTPUT_DIR)
# build rule
$(CONVERTER_OUTPUT_DIR)/applet.cap: $(JAVA_CLASS_FILES)
	"$(JC_HOME)/bin/converter" $(CONVERTER_FLAGS) -classdir $(OUTPUT_DIR) -out EXP JCA CAP -exportpath $(EXPORT_PATH) -applet $(AID) $(APPLET_QUALIFIED_CLASS_NAME) -d $(OUTPUT_DIR) $(PACKAGE) $(PID) $(MAJOR_VERSION).$(MINOR_VERSION) 
	-@mkdir -p .libs
	unzip -j -d $(OUTPUT_DIR)  $(CONVERTER_OUTPUT_DIR)/applet.cap	
	cat  $(OUTPUT_DIR)/Header.cap  $(OUTPUT_DIR)/Directory.cap  $(OUTPUT_DIR)/Import.cap  $(OUTPUT_DIR)/Applet.cap  $(OUTPUT_DIR)/Class.cap $(OUTPUT_DIR)/Method.cap  $(OUTPUT_DIR)/StaticField.cap  $(OUTPUT_DIR)/ConstantPool.cap  $(OUTPUT_DIR)/RefLocation.cap  $(OUTPUT_DIR)/Descriptor.cap > .libs/CardEdge.ijc
	mv .libs/CardEdge.ijc .libs/CardEdge.$(shell cat .buildid).ijc


#############################################################################



#############################################################################
# Verify CAP file
#############################################################################

verifycapfile:
	"$(JC_HOME)/bin/verifycap" $(VERIFIER_FLAGS) -package $(PACKAGE) "$(GP_HOME)/org/globalplatform/javacard/globalplatform.exp" "$(JC_HOME)/api_export_files/java/lang/javacard/lang.exp" "$(JC_HOME)/api_export_files/javacard/framework/javacard/framework.exp" "$(JC_HOME)/api_export_files/javacard/security/javacard/security.exp" "$(JC_HOME)/api_export_files/javacardx/crypto/javacard/crypto.exp" $(CONVERTER_OUTPUT_DIR)/applet.cap 

#############################################################################
