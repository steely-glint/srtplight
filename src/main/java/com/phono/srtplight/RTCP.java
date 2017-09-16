/*
 * Copyright 2017 |pipe|
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

import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 *
 * @author thp
 */
public class RTCP {

    final static int SR = 200;
    final static int RR = 201;
    final static int SDES = 202;
    final static int BYE = 203;
    final static int RTPFB = 205;

    /*
            0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=SR=200   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
sender |              NTP timestamp, most significant word             |
info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             NTP timestamp, least significant word             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         RTP timestamp                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     sender's packet count                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      sender's octet count                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    static public RTCP mkRTCP(DatagramPacket pkt) throws InvalidRTCPPacketException {
        RTCP ret = null;
        
        int len = pkt.getLength();
        byte [] data = new byte[len];
        System.arraycopy(pkt.getData(), 0, data, 0, len);
        Log.debug("RTCP packet "+ SRTPProtocolImpl.getHex(data));
        ByteBuffer bb = ByteBuffer.wrap(data);
        char fh = bb.getChar();
        int v = (fh & ((char) (0xc000))) >>> 14;
        int p = (fh & ((char) (0x2000))) >>> 13;
        int rc = (fh & ((char) (0x1f00))) >>> 8;
        int pt = (char) (fh & ((char) (0x00ff)));
        int length = bb.getChar();
        Log.debug("Have RTCP pkt with v=" + v + " p=" + p + " rc=" + rc + " pt=" + pt + " lenght=" + length);
        if (v != 2) {
            throw new InvalidRTCPPacketException("version must be 2");
        }
        int offset = (length *4);
        int tail = bb.remaining() - offset;
        if (tail > 0){
            Log.debug("have tail bytes "+ tail);
            parseTail(bb,offset,tail);
        }
        switch (pt) {
            case SR:
                ret = new SenderReport(bb, rc, length);
                break;
            case RR:
                ret = new ReceiverReport(bb, rc, length);
                break;
            case SDES:
                ret = new SDES(bb, rc, length);
                break;
            case BYE:
                ret = new BYE(bb, rc, length);
                break;
            case RTPFB:
                ret = new FB(bb, rc, length);
                break;
            default:
                Log.debug("Ignoring unknown RTCP type =" + pt);
                break;
        }
        return ret;
    }

    public static void main(String[] args) {
        Log.setLevel(Log.ALL);
        byte[] sr = {(byte) 0x80, (byte) 0xc8, (byte) 0x00, (byte) 0x06, (byte) 0x50, (byte) 0xf6, (byte) 0xb8, (byte) 0xbf, (byte) 0xdd, (byte) 0x62, (byte) 0x47, (byte) 0xcd, (byte) 0x4b, (byte) 0x43, (byte) 0x95, (byte) 0x81,
            (byte) 0x27, (byte) 0x9b, (byte) 0xca, (byte) 0xef, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] rr = {(byte) 0x81, (byte) 0xc9, (byte) 0x00, (byte) 0x07, (byte) 0xab, (byte) 0x36, (byte) 0xcd, (byte) 0x19, (byte) 0x2e, (byte) 0x0f, (byte) 0x36, (byte) 0x14, (byte) 0xa0, (byte) 0xfb, (byte) 0xf0, (byte) 0xe5, (byte) 0x5a, (byte) 0x50, (byte) 0x0b, (byte) 0xc0, (byte) 0x1a, (byte) 0xc9, (byte) 0x52, (byte) 0xbc, (byte) 0x61, (byte) 0x36, (byte) 0x57, (byte) 0xd5, (byte) 0x5f, (byte) 0x19, (byte) 0x00, (byte) 0xa4
        };
        byte[] fb = {(byte) 0x8f, (byte) 0xcd, (byte) 0x00, (byte) 0x06, (byte) 0x75, (byte) 0xe8, (byte) 0x1d, (byte) 0x8f, (byte) 0x04, (byte) 0xad, (byte) 0xa0, (byte) 0xf2, (byte) 0xda, (byte) 0x59, (byte) 0x26, (byte) 0x25, (byte) 0x30, (byte) 0xee, (byte) 0x6e, (byte) 0x9f, (byte) 0x71, (byte) 0x36, (byte) 0x82, (byte) 0x61, (byte) 0xfb, (byte) 0xe4, (byte) 0x12, (byte) 0x80};
        byte[][] tests = {sr, rr, fb};
        for (byte[] t : tests) {
            DatagramPacket p = new DatagramPacket(t, t.length);
            try {
                RTCP r = mkRTCP(p);
                if (r != null) {
                    Log.debug(r.toString());
                } else {
                    Log.error("r is null");
                }
            } catch (InvalidRTCPPacketException irp) {
                Log.error(irp.getMessage());
                irp.printStackTrace();
            }
        }
    }

    private static void parseTail(ByteBuffer bb, int offset, int tail) {
  /*
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |E|                         SRTCP index                         | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
   | ~                     SRTCP MKI (OPTIONAL)                      ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | :                     authentication tag                        : |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   */
        int opos = bb.position();
        int mkti= 0;
        long authtag = 0;
        bb.position(offset);
        long index = bb.getInt();
        boolean encryption = (index < 0);
        index = (0x7fffffff & index);
        if(bb.remaining() > 4){
            mkti = bb.getInt();
        }
        if(bb.remaining() > 4){
            authtag = bb.getInt();
        }
        Log.debug("Tail ="+tail+" index="+index+" mkti="+mkti+" authtag="+authtag+" encryption="+encryption);
        //checkauth();
        bb.position(opos);
    }

    private static class SenderReport extends RTCP {

        /*
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
sender |              NTP timestamp, most significant word             |
info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             NTP timestamp, least significant word             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         RTP timestamp                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     sender's packet count                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      sender's octet count                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */
        long ssrc;
        long ntpstamp;
        long rtpstamp;
        long senderPkts;
        long senderOcts;
        ArrayList<ReportBlock> reports;

        public SenderReport(ByteBuffer bb, int rc, int length) throws InvalidRTCPPacketException {
            int expected = 6 + (6 * rc);
            if (length != expected) {
                throw new InvalidRTCPPacketException("length mismatch expected=" + expected + " got length=" + length);
            }

            ssrc = bb.getInt();
            ntpstamp = bb.getLong();
            rtpstamp = bb.getInt();
            senderPkts = bb.getInt();
            senderOcts = bb.getInt();
            reports = new ArrayList();
            for (int i = 0; i < rc; i++) {
                ReportBlock rblock = new ReportBlock(bb);
                reports.add(rblock);
            }
        }

        public String toString() {
            String ret = "RTCP SR: ssrc=" + ssrc + " ntpstamp=" + ntpstamp + " rtpstamp=" + rtpstamp + " senderPkts=" + senderPkts + " senderOcts=" + senderOcts;
            for (ReportBlock b : reports) {
                ret += "\n\t" + b.toString();
            }
            return ret;
        }

    }

    private static class ReceiverReport extends RTCP {

        /*
                0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=RR=201   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     SSRC of packet sender                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         */
        long ssrc;
        ArrayList<ReportBlock> reports;

        public ReceiverReport(ByteBuffer bb, int rc, int length) throws InvalidRTCPPacketException {
            int expected = 1 + (6 * rc);
            Log.debug("length expected=" + expected + " got length=" + length + " rc = " + rc);

            if (length != expected) {
                throw new InvalidRTCPPacketException("length mismatch expected=" + expected + " got length=" + length);
            }

            ssrc = bb.getInt();
            reports = new ArrayList();
            for (int i = 0; i < rc; i++) {
                ReportBlock rblock = new ReportBlock(bb);
                reports.add(rblock);
            }
        }

        public String toString() {
            String ret = "RTCP RR: ssrc=" + ssrc;
            for (ReportBlock b : reports) {
                ret += "\n\t" + b.toString();
            }
            return ret;
        }
    }

    private static class SDES extends RTCP {

        public SDES(ByteBuffer bb, int rc, int length) {
        }
    }

    private static class BYE extends RTCP {

        public BYE(ByteBuffer bb, int rc, int length) {
        }
    }

    private static class FB extends RTCP {

        long sssrc;
        long mssrc;
        private int fmt;
        private byte[] fci;

        /*
           Figure 3:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|   FMT   |       PT      |          length               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  SSRC of packet sender                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  SSRC of media source                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   :            Feedback Control Information (FCI)                 :
   :                                                               :
         */
        public FB(ByteBuffer bb, int rc, int length) throws InvalidRTCPPacketException {
            if (length < 2) {
                throw new InvalidRTCPPacketException("length expected at least 2 got " + length);
            }
            sssrc = bb.getInt();
            mssrc = bb.getInt();
            fmt = rc;
            fci = new byte[(length - 2) * 4];
            bb.get(fci);
        }

        public String toString() {
            String ret = "RTCP FB: sssrc=" + sssrc + " mssrc=" + mssrc + " fmt=" + fmt + " fci length=" + fci.length;
            return ret;
        }
    }

    class ReportBlock {

        /*
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */
        long ssrc;
        int frac;
        int cumulost;
        long highestSeqRcvd;
        long iaJitter;
        long lsr;
        long dlsr;

        ReportBlock(ByteBuffer bb) {
            ssrc = bb.getInt();
            char c3 = bb.getChar();
            char c4 = bb.getChar();
            frac = c3 & 0xff00 >>> 8;
            cumulost = c4 + ((c3 & 0xff) << 16);
            highestSeqRcvd = bb.getInt();
            iaJitter = bb.getInt();
            lsr = bb.getInt();
            dlsr = bb.getInt();
        }

        public String toString() {
            return "ReportBlock for ssrc=" + ssrc + " frac=" + frac + " cumulost=" + cumulost + " highestSeqRcvd=" + highestSeqRcvd + " iaJitter=" + iaJitter + " lsr=" + lsr + " dlsr=" + dlsr;
        }

    }

}
