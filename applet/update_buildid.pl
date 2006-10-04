#!/usr/bin/perl
#
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

use strict;
my $file;
my $line;
my $cvsuser        = $ENV{'CVSUSER'} ;
my $buildid        = time();
my $buildid_major;
my $buildid_minor;
my $version_major;
my $version_minor;

foreach $file (@ARGV) {
    findVersion($file);
}

if ($cvsuser ne 'robobld') {
    $buildid_major = ($buildid >> 16) & 0xffff;
    $buildid_minor = $buildid & 0xffff;
}

printf ("buildID: %d.%d.%04x%04x\n", 
	$version_major, $version_minor, $buildid_major, $buildid_minor);

open OUTPUT, ">.buildid" or die;
printf OUTPUT "%d.%d.%04x%04x", 
	$version_major, $version_minor, $buildid_major, $buildid_minor;
close OUTPUT;

if ($cvsuser ne 'robobld') {
    $buildid_major = sprintf("0x%04x", $buildid_major);
    $buildid_minor = sprintf("0x%04x", $buildid_minor);
    foreach $file (@ARGV) {
	replaceBuildId($file);
    }
}

sub findVersion
{
    my $file = $_[0];

#   printf("findVersion: file = %s\n", $file);
    open INPUT, "<$file" or die;
    while ($line = <INPUT>) {
        if( $line =~ /VERSION_APPLET_MAJOR\s*=\s*([0-9]*)\s*;/ ) {
            $version_major = $1;
        }
        if( $line =~ /VERSION_APPLET_MINOR\s*=\s*([0-9]*)\s*;/ ) {
            $version_minor = $1;
        }
        if( $line =~ /BUILDID_MAJOR\s*=.*(0x[0-9a-fA-F]{4})\s*;/ ) {
            $buildid_major = eval($1);
        }
        if( $line =~ /BUILDID_MINOR\s*=.*(0x[0-9a-fA-F]{4})\s*;/ ) {
            $buildid_minor = eval($1);
        }
    }
    close INPUT;
}

sub replaceBuildId
{
    my $file = $_[0];

#   printf("replaceBuildID: file = %s\n", $file);
    open INPUT, "<$file" or die;
    open OUTPUT, ">$file.new" or die;

    while($line = <INPUT>) {
        # This shouldn't be necessary, but Perl isn't automatically stripping
        # out the CRs on my PC.
        $line =~ s/\r//g;

        if( $line =~ /BUILDID_MAJOR\s*=.*(0x[0-9a-fA-F]{4})\s*;/ ) {
            $line =~ s/$1/$buildid_major/;
        }
        if( $line =~ /BUILDID_MINOR\s*=.*(0x[0-9a-fA-F]{4})\s*;/ ) {
            $line =~ s/$1/$buildid_minor/;
        }
        print OUTPUT $line;
    }
    print "mv $file.new $file\n";
    close INPUT; close OUTPUT;
    rename "$file.new", $file or die;
}
