/*
 * Copyright 2025 |pipe|
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
package com.phono.srtplight.rtcp;

import com.phono.srtplight.BitUtils;
import com.phono.srtplight.Log;
import java.nio.ByteBuffer;
import static com.phono.srtplight.SRTPProtocolImpl.getHex;

/**
 *
 * @author tim
 */
public class REMB {
    public static int FMT = 15; 
    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |V=2|P| FMT=15  |   PT=206      |             length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  SSRC of packet sender                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  SSRC of media source                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Unique identifier 'R' 'E' 'M' 'B'                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Num SSRC     | BR Exp    |  BR Mantissa                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   SSRC feedback                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  ...                                                          |
     */
    public static long getBwe(byte[] fci) {
        long bwe = 0;
        int remb = 0x52454d42;
        if (fci.length >= 12) {
            ByteBuffer bb = ByteBuffer.wrap(fci);
            int sig = bb.getInt();
            int val = bb.getInt();
            int ssrc = bb.getInt();
            if (sig == remb) {
                Log.verb("got remb data");
                int mant = val & 0x3ffff;
                int exp = (val & 0xfc0000) >> 18;
                int ssrcn = (val & 0xf0000000) >> 24;
                bwe = mant << exp;
                Log.verb("bwe =" + bwe + " mant =" + mant + " exp=" + exp + " srcn=" + ssrcn+ " ssrc = "+ssrc);
            } else {
                Log.warn("not remb");
            }
        }
        return bwe;
    }

    public static byte[] makeBwe(long bwe,long ssrc) {
        byte[] fci = new byte[12];
        byte sig[] = {(byte) 0x52, (byte) 0x45, (byte) 0x4d, (byte) 0x42};
        int offs = 0;
        for (byte v : sig) {
            fci[offs++] = v;
        }
        int topBit = 31;
        while ((bwe & (1 << topBit)) == 0) {
            topBit--;
        }
        if (topBit < 17) {
            topBit = 17;
        }
        int exp = topBit - 17;
        Log.info("exp = " + exp);
        int mant = (int) (bwe >>> exp);
        Log.info("mant = " + mant);
        int sn =1;
        BitUtils.copyBits(sn, 8, fci,32);
        BitUtils.copyBits(exp, 6, fci,40);
        BitUtils.copyBits(mant, 18, fci,46);
        BitUtils.copyBits((int)ssrc, 32, fci,64);
        return fci;
    }

    final public static void main(String argv[]) {
        Log.setLevel(Log.ALL);
        long [] ts = {50000,128000,512000,750000,2111000,3333333,10000000};
        byte[] tb1 = {(byte) 0x52, (byte) 0x45, (byte) 0x4d, (byte) 0x42, (byte) 0x01, (byte) 0x13, (byte) 0x12, (byte) 0x75, (byte) 0x4f, (byte) 0x5d, (byte) 0xa4, (byte) 0x0f};
        long t1 = REMB.getBwe(tb1);
        Log.info("t1 ="+t1);
        byte []fci =  REMB.makeBwe(t1,0x4f5da40f);
        Log.info("Fci is "+getHex(fci));
        long t2 = REMB.getBwe(fci);
        Log.info("t2 ="+t2);
        for (long t:ts){
            byte[] f =  REMB.makeBwe(t,0x4f5da40f);
            long ta = REMB.getBwe(f);
            Log.info("t="+t+" ta="+ta);
        }
    }

}
