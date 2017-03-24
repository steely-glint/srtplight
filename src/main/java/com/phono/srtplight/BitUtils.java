/*
 * Copyright 2011 Voxeo Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.phono.srtplight;


public class BitUtils  {

    /**
     * Set bit number (bitno) to one. The bit numbering pretends the
     * byte array is one very long word.
     *
     * @param output The output array to set the bit
     * @param bitno The position of the bit (in output)
     */
    public static void setBit(byte output[], int bitno)
    throws java.lang.ArrayIndexOutOfBoundsException {
        // bit 0 is on the left hand side, if bit 0 should be set to '1'
        // this would show as: 1000 0000 = 0x80
        
        // each byte is 8 bits
        int index = bitno / 8;
        int index_bitno = bitno % 8;
        
        // shift the '1' into the right place
        // shift with zero extension
        byte mask = (byte) (0x80 >>> index_bitno);
        
        // OR the bit into the byte, so the other bits remain
        // undisturbed.
        output[index] |= mask;
    }
    
    /**
     * Copies a number of bits from input to output.
     * Copy bits from left to right (MSB - LSB).
     *
     * @param input The input value to read from
     * @param in_noLSB The number of LSB in input to copy
     * @param output The output array to copy the bits to
     * @param out_pos The start position in output
     * @return the updated out_pos
     */
    public static int copyBits(int input, int in_noLSB, byte output[],
            int out_pos) {
        int res;
        int value = input;
        
        // start with the left most bit I've got to copy over:
        int mask = 0x1 << (in_noLSB -1);
        
        for (int i=0; i<in_noLSB; i++) {
            // see if the that bit is one or zero
            res = (value & mask);
            if (res > 0) {
                setBit(output, out_pos);
            }
            
            // shift the mask to the next position
            // shift with zero extension
            mask = mask >>> 1;
            out_pos++;
        }
        return out_pos;
    }
    
    
    
    /**
     * Returns zero or one.
     *
     * @param input The input array to read from
     * @param bitno The position of the bit (in input)
     * @return one or zero
     */
    public static int getBit(byte input[], int bitno)
    throws java.lang.ArrayIndexOutOfBoundsException {
        // bit 0 is on the left hand side, if bit 0 should be set to '1'
        // this would show as: 1000 0000 = 0x80
        
        // each byte is 8 bits
        int index = bitno / 8;
        int index_bitno = bitno % 8;
        
        byte onebyte = input[index];
        
        // shift the '1' into the right place
        // shift with zero extension
        byte mask = (byte) (0x80 >>> index_bitno);
        
        // mask (AND) it so see if the bit is one or zero
        int res = (onebyte & mask);
        if (res < 0) {
            // it can be negative when testing the signed bit (bit zero
            // in this case)
            res = 1;
        }
        return res;
    }
    
    
    /**
     * Copy a number of bits from input into a short.
     * Copy bits from left to right (MSB - LSB).
     *
     * @param input The input array to read from
     * @param in_pos The position of the bit (in input) to start from
     * @param no_bits The number of bits to copy
     * @return The new value as a short
     */
    public static short copyBits(byte input[], int in_pos,
            int no_bits) {
        // LSB is on the right hand side
        short out_value = 0;
        
        // start with the left most bit I've got to copy into:
        int out_value_mask = 0x1 << (no_bits -1);
        
        int myBit;
        for (int b=0; b<no_bits; b++) {
            myBit = getBit(input, in_pos);
            if (myBit > 0) {
                // OR the bit into place, so the other bits remain
                // undisturbed.
                out_value |= out_value_mask;
            }
            
            // move to the next bit of input
            in_pos++;
            
            // get ready for the next bit of output
            // shift with zero extension
            out_value_mask = (short) (out_value_mask >>> 1);
        }
        return out_value;
    }

    
}
