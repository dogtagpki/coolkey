//  SmartCard Applet
//      Authors:          Robert Relyea     <rrelyea@redhat.com>
//      Package:          CardEdgeApplet
//      Description:      CardEdge implementation with JavaCard
//
// BEGIN LICENSE BLOCK
// Copyright (C) 2006 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// Changes to this license can be made only by the copyright author with
// explicit written consent.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Alternatively, the contents of this file may be used under the terms of
// the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
// case the provisions of the LGPL are applicable instead of those above. If
// you wish to allow use of your version of this file only under the terms
// of the LGPL, and not to allow others to use your version of this file
// under the terms of the BSD license, indicate your decision by deleting
// the provisions above and replace them with the notice and other
// provisions required by the LGPL. If you do not delete the provisions
// above, a recipient may use your version of this file under the terms of
// either the BSD license or the LGPL.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
// END LICENSE_BLOCK

package com.redhat.ckey.applet;

//import javacard.framework.ISOException;
//import javacard.framework.JCSystem;
import javacard.framework.Util;

// Represent and unsigned 64 quantity as a list of 8 short quantities stored in memory.
// All that is needed is a decrement operation and XOR operation for the AES KWP alg.
// What we have here is an array of shorts, taking up 16 bytes (or 2 per short) that is used
// to represent an Unsigned 64 bit integer. Each short is acting as an unsigned byte in the 8 byte Unsigned64
// data type we might see in the C language.
//
// The data (16 bytes) holding the values is set externally from outside memory (transient) with an offset
// to said data.
//
// The reason for the array of shorts is because we want to only rely upon the signed short java data type
// present in many tokens.
class Unsigned64 {
        //The number of bytes used to represent the 8 "unsigned bytes" we impersonate.
	private final short MAX_BYTE_LEN = (short) 16;
	//The number of short values this class supports.
	private final short MAX_SHORT_LEN = (short) 8;
	//The number of bits in a byte , used for shifting purposes
	private final short BITS_IN_BYTE = (short) 8;
        //Make public for efficiency copying one object to another
	public byte[] data = null;
	public short dataOffset = 0;

        Unsigned64() {
        }

	// Set the actual data for the Unsigned64 from the outside.
	// This allows us to offset into a previously created transient
	// memory buffer, which prevents over use of persistent memory
	// and also executes much more quickly.
	public void setData(byte[] input, short inOffset) {
            data = input;
	    dataOffset = inOffset;
	}

        //set the value from an array of bytes
	//This takes a block of actual bytes and takes each one
	//and makes a short out of it internally. Data and offset into
	//data are provided.
        public void setFromBytes(byte[] input, short offset) {
            if(input == null || offset < 0) {
                return;
            }

	    short val = 0;
	    for(short i = 0 ; i < MAX_SHORT_LEN ; i++) {
                val = Util.makeShort((byte) 0x0, input[(short) (i+offset)]);
	        setShortAt(i,val);
	    }
        }

        // Set the values to 0
        public void clear() {
	    Util.arrayFillNonAtomic(data, (short) dataOffset, (short) MAX_BYTE_LEN,(byte) 0);
        }

	//Get the value as a byte array, being placed into the output buffer.
	//This takes the short values and writes each one external memory at a given
	//offset.
	//For intance each short value (8) will be written as bytes (8) into the desired location.
        public void getBytes(byte[] output, short offset) {
            if(output == null || ((short) (offset + MAX_SHORT_LEN)) > output.length) {
                return;
            }

	    short bOffset = dataOffset;
	    short val = 0;
	    for (short i = 0; i < MAX_SHORT_LEN ; i++) {
	        val = getShortAt(i);
		output[(short) (offset + i)] = (byte) val;
	    }
        }

	//Set the value based on an input short value
	//Since we know the value will never be more than an unsigned short
	//proceed to break up the value into two bytes and import into the object
	//as two shorts placed in the final two index slots in the array.
        public void setFromShort(short in) {
            if(in < 0) {
                return;
            }
	    short index1 = (short) (MAX_SHORT_LEN - 2);
	    short index2 = (short) (MAX_SHORT_LEN - 1);

	    clear();
	    setShortAt((short) index1 ,(short)(in >> BITS_IN_BYTE));
	    setShortAt((short) index2, (short) (in & 0x00ff));
        }

	//Set an Unsigned64 to be the same value as another Unsigned64
        public void setFrom(Unsigned64 input) {
            Util.arrayCopyNonAtomic(input.data, input.dataOffset, data, dataOffset,(short) MAX_BYTE_LEN);
        }

        //Change the values of this instance after xor
        public void XOR(Unsigned64 b) {
	   short aVal = 0;
	   short bVal = 0;
	   for(short i = 0 ; i < MAX_SHORT_LEN; i++) {
	       bVal = b.getShortAt(i);
	       aVal = getShortAt(i);
	       setShortAt(i,(short) (aVal ^ bVal));
	   }
        }

        //Change the values of target after xor
        public void XOR(Unsigned64 b, Unsigned64 target) {
	    target.XOR(b);
        }

	//Set one of the members of the array of shorts to input value
        public void setShortAt(short index, short val) {
            // No checking for efficiency and is used internally
	    Util.setShort(data,(short) (dataOffset + 2 * index),val);
        }

        //Get the short value at a given index
        public short getShortAt(short index)  {
            //No checking for efficiency and this is used internally
	    return  Util.getShort(data,(short) (dataOffset + 2 * index));
        }
 
	//Determine if one Unsigned64 is equal to another
        public boolean isEqualTo(Unsigned64 B) {
            if(B == null)
                return false;

	    for(short i = 0 ; i < MAX_SHORT_LEN; i++) {
		if(getShortAt(i) != B.getShortAt(i))
		    return false;
	    }
            return true;
        }

	//Decrement the value by one
	//This manually traverses the array of shorts and does
	//what is needed to end up with a new Unsigned64 with one less
	//in value.
        public boolean decrement() {
            short last = lastNonZero();
            if(last == -1) { // all zeroes
                return false;
            }

	    short cur = getShortAt(last);
	    setShortAt(last, (short) (cur -1));

            if(last < 7) { //
                fillRangeWith((short) (last + 1),(short) 7,(short) 255);
            }

            return true;
        }

	//Internal routine to find last non zero array member
        private short lastNonZero() {
	    for(short i = 7 ; i >= 0 ; i--) {
                if(getShortAt(i) != 0) {
                    return i;
                }
            }
            return -1;
        }

	//Internal routine to fill a range of the array with a given value
        private void fillRangeWith(short start, short end, short val) {

           if(start > end || start < 0
                || end < 0 || end >= MAX_SHORT_LEN) {
               return;
           }

	   for (short i = start ; i <= end ; i++) {
              setShortAt(i , val);
           }
        }

	//Check to see if the Unsigned64 is of zero value
//        public boolean isZero() {
//	   for(short i = 0 ; i < MAX_SHORT_LEN ; i++) {
//              if(getShortAt(i) != 0)
//                  return false;
//           }
//           return true;
//        }
}

