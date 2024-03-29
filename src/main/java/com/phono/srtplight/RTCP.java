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

import static com.phono.srtplight.SRTPProtocolImpl.getHex;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

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
    final static int PSFB = 206;



    protected char pt;
    protected long ssrc;

    void addBody(ByteBuffer bb) {
        int pad = 0;
        int rc = this.getRC();
        int llen = this.estimateBodyLength();
        byte[] head = new byte[4];
        BitUtils.copyBits(2, 2, head, 0);
        BitUtils.copyBits(pad, 1, head, 2);
        BitUtils.copyBits(rc, 5, head, 3);
        BitUtils.copyBits(pt, 8, head, 8);
        BitUtils.copyBits(llen, 16, head, 16);
        bb.put(head);
        bb.putInt((int) ssrc);
    }

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
    static public RTCP mkRTCP(ByteBuffer bb) throws InvalidRTCPPacketException {
        RTCP ret = null;
        int begin = ((Buffer) bb).position();
        char fh = bb.getChar();
        int v = (fh & ((char) (0xc000))) >>> 14;
        int p = (fh & ((char) (0x2000))) >>> 13;
        int rc = (fh & ((char) (0x1f00))) >>> 8;
        int lpt = (char) (fh & ((char) (0x00ff)));
        int length = bb.getChar();
        Log.verb("Have RTCP pkt with v=" + v + " p=" + p + " rc=" + rc + " pt=" + lpt + " lenght=" + length);
        if (v != 2) {
            throw new InvalidRTCPPacketException("version must be 2");
        }
        int offset = (length * 4);
        switch (lpt) {
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
                ret = new RTPFB(bb, rc, length);
                break;
            case PSFB:
                ret = new PSFB(bb, rc, length);
                break;
            default:
                ret = new RTCP();
                Log.debug("Ignoring unknown RTCP type =" + lpt);
                break;
        }
        ((Buffer) bb).position(begin + offset + 4);
        return ret;
    }

    public static void main(String[] args) {
        Log.setLevel(Log.ALL);
        byte[] sr = {(byte) 0x80, (byte) 0xc8, (byte) 0x00, (byte) 0x06, (byte) 0x50, (byte) 0xf6, (byte) 0xb8,
            (byte) 0xbf, (byte) 0xdd, (byte) 0x62, (byte) 0x47, (byte) 0xcd, (byte) 0x4b, (byte) 0x43, (byte) 0x95, (byte) 0x81,
            (byte) 0x27, (byte) 0x9b, (byte) 0xca, (byte) 0xef, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] rr = {(byte) 0x81, (byte) 0xc9, (byte) 0x00, (byte) 0x07, (byte) 0xab, (byte) 0x36, (byte) 0xcd,
            (byte) 0x19, (byte) 0x2e, (byte) 0x0f, (byte) 0x36, (byte) 0x14, (byte) 0xa0, (byte) 0xfb, (byte) 0xf0,
            (byte) 0xe5, (byte) 0x5a, (byte) 0x50, (byte) 0x0b, (byte) 0xc0, (byte) 0x1a, (byte) 0xc9, (byte) 0x52,
            (byte) 0xbc, (byte) 0x61, (byte) 0x36, (byte) 0x57, (byte) 0xd5, (byte) 0x5f, (byte) 0x19, (byte) 0x00, (byte) 0xa4
        };
        byte[] fb = {(byte) 0x8f, (byte) 0xcd, (byte) 0x00, (byte) 0x06, (byte) 0x75, (byte) 0xe8, (byte) 0x1d, (byte) 0x8f,
            (byte) 0x04, (byte) 0xad, (byte) 0xa0, (byte) 0xf2, (byte) 0xda, (byte) 0x59, (byte) 0x26, (byte) 0x25, (byte) 0x30,
            (byte) 0xee, (byte) 0x6e, (byte) 0x9f, (byte) 0x71, (byte) 0x36, (byte) 0x82, (byte) 0x61, (byte) 0xfb, (byte) 0xe4,
            (byte) 0x12, (byte) 0x80};
        byte[][] tests = {sr, rr, fb};
        for (byte[] t : tests) {
            ByteBuffer p = ByteBuffer.wrap(t);
            try {
                RTCP r = mkRTCP(p);
                if (r != null) {
                    Log.verb(r.toString());
                } else {
                    Log.error("r is null");
                }
            } catch (InvalidRTCPPacketException irp) {
                Log.error(irp.getMessage());
                irp.printStackTrace();
            }
        }
        SenderReport sro = mkSenderReport();
        sro.setSSRC(1358346431);
        sro.setNTPStamp(-2494352296553245311L);
        sro.setRTPStamp(664521455);
        sro.setSenderPackets(0);
        sro.setSenderOctets(0);
        int ebl = sro.estimateBodyLength();
        ByteBuffer bbo = ByteBuffer.allocate(4 * (ebl + 1));
        sro.addBody(bbo);
        byte[] pky = bbo.array();
        Log.verb("sro " + sro);
        Log.verb("sro " + getHex(pky));
        for (int i = 0; i < sr.length; i++) {
            if (pky[i] != sr[i]) {
                Log.error("packets differ at:" + i);
            }
        }
        ReceiverReport rro = mkReceiverReport();
        ebl = sro.estimateBodyLength();
        bbo = ByteBuffer.allocate(4 * (ebl + 1));
        rro.addBody(bbo);
        pky = bbo.array();
        Log.verb("rro " + rro);
        Log.verb("rro " + getHex(pky));
        
        PSFB p = mkPSFB();
        p.setSSRC(0x12345678);
        p.setMssrc(0x23456789);
        p.setSssrc(0x3456789A);
        p.setFmt(1);
        p.setFci(new byte[0]);
        int pl = p.estimateBodyLength();
        bbo = ByteBuffer.allocate(4 * (pl + 1));
        p.addBody(bbo);
        byte[] pa = bbo.array();
        Log.info("PSFB " + p);
        Log.info("PSFB " + getHex(pa));
        try {
            bbo.flip();
            RTCP p2 = mkRTCP(bbo);
            Log.info("PSFB "+p2.toString());
        } catch (Exception x){
            Log.warn("cant parse PSFB");
            x.printStackTrace();
        }
        
    }

    public static SenderReport mkSenderReport() {
        SenderReport ret = new SenderReport();
        return ret;
    }

    static ReceiverReport mkReceiverReport() {
        ReceiverReport ret = new ReceiverReport();
        return ret;
    }

    static PSFB mkPSFB() {
        PSFB ret = new PSFB();
        return ret;
    }
    int estimateBodyLength() { // this is int 32s -1
        return 1;
    }

    public void setSSRC(long s) {
        ssrc = s;
    }

    int getRC() {
        return 0;
    }

    static class SenderReport extends RTCP {

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
        long ntpstamp;
        long rtpstamp;
        long senderPkts;
        long senderOcts;
        ArrayList<ReportBlock> reports;

        public void setNTPStamp(long s) {
            ntpstamp = s;
        }

        public void setRTPStamp(long s) {
            rtpstamp = s;
        }

        public void setSenderPackets(long s) {
            senderPkts = s;
        }

        public void setSenderOctets(long s) {
            senderOcts = s;
        }

        public void addReport(ReportBlock b) {
            reports.add(b);
        }

        @Override
        public void addBody(ByteBuffer bb) {
            super.addBody(bb);
            bb.putLong(ntpstamp);
            bb.putInt((int) rtpstamp);
            bb.putInt((int) senderPkts);
            bb.putInt((int) senderOcts);
            for (ReportBlock r : reports) {
                r.addBody(bb);
            }
        }

        @Override
        int getRC() {
            return reports.size();
        }

        @Override
        int estimateBodyLength() {
            return 6 + (6 * reports.size());
        }

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

        private SenderReport() {
            reports = new ArrayList();
            pt = SR;
        }

        public String toString() {
            String ret = "RTCP SR: ssrc=" + ssrc + " ntpstamp=" + ntpstamp + " rtpstamp=" + rtpstamp + " senderPkts=" + senderPkts + " senderOcts=" + senderOcts;
            for (ReportBlock b : reports) {
                ret += "\n\t" + b.toString();
            }
            return ret;
        }

    }

    public static class ReceiverReport extends RTCP {

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
            Log.verb("length expected=" + expected + " got length=" + length + " rc = " + rc);

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

        @Override
        public void addBody(ByteBuffer bb) {
            super.addBody(bb);
        }

        @Override
        int getRC() {
            return reports.size();
        }

        @Override
        int estimateBodyLength() {
            return 6 + (6 * reports.size());
        }

        private ReceiverReport() {
            reports = new ArrayList();
            pt = RR;
        }

        public ReportBlock[] getReports() {
            ReportBlock[] ret = new ReportBlock[reports.size()];
            for (int i = 0; i < reports.size(); i++) {
                ret[i] = reports.get(i);
            }
            return ret;
        }

        public String toString() {
            String ret = "RTCP RR: ssrc=" + ssrc;
            for (ReportBlock b : reports) {
                ret += "\n\t" + b.toString();
            }
            return ret;
        }
    }

    public RTCP() {
    }

    public static class SDES extends RTCP {

        public SDES(ByteBuffer bb, int rc, int length) {
        }
    }

    public static class BYE extends RTCP {

        public BYE(ByteBuffer bb, int rc, int length) {
        }
    }

    public static class FB extends RTCP {

        protected long sssrc;
        protected long mssrc;
        protected int fmt;
        protected byte[] fci;

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

        protected FB() {
            super();
        }
        @Override
        public void addBody(ByteBuffer bb) {
            super.addBody(bb);
            bb.putInt((int)mssrc);
            bb.put(fci);
        }
        
        public long getSssrc() {
            return sssrc;
        }

        public long getMssrc() {
            return mssrc;
        }

        public int getFmt() {
            return fmt;
        }
        @Override
        public int getRC() {
            return fmt;
        }
        public byte[] getFci() {
            return fci;
        }

        @Override
        public String toString() {
            String ret = "RTCP FB: sssrc=" + sssrc + " mssrc=" + mssrc + " fmt=" + fmt + " fci length=" + fci.length;
            return ret;
        }


        @Override
        int estimateBodyLength() {
            return (fci.length/4) + 2;
        }
        /**
         * @param sssrc the sssrc to set
         */
        public void setSssrc(long sssrc) {
            this.sssrc = sssrc;
        }

        /**
         * @param mssrc the mssrc to set
         */
        public void setMssrc(long mssrc) {
            this.mssrc = mssrc;
        }

        /**
         * @param fmt the fmt to set
         */
        public void setFmt(int fmt) {
            this.fmt = fmt;
        }

        /**
         * @param fci the fci to set
         */
        public void setFci(byte[] fci) {
            this.fci = fci;
        }
    }

    public static class PSFB extends FB {

        public PSFB(ByteBuffer bb, int rc, int length) throws InvalidRTCPPacketException {
            super(bb, rc, length);
        }

        protected PSFB() {
            super();
            pt = PSFB;
        }

        public String toString() {
            String ret = "RTCP PSFB: sssrc=" + sssrc + " mssrc=" + mssrc + " fmt=" + fmt + " fci length=" + fci.length;
            return ret;
        }

        @Override
        public void addBody(ByteBuffer bb) {
            super.addBody(bb);
        }

        @Override
        int estimateBodyLength() {
            return super.estimateBodyLength();
        }
    }

    public static class RTPFB extends FB {

        public RTPFB(ByteBuffer bb, int rc, int length) throws InvalidRTCPPacketException {
            super(bb, rc, length);
        }

        public String toString() {
            String ret = "RTCP RTPFB: sssrc=" + sssrc + " mssrc=" + mssrc + " fmt=" + fmt + " fci length=" + fci.length;
            return ret;
        }

        public List<Long> getSeqList() {
            ArrayList<Long> ret = new ArrayList();
            ByteBuffer bb = ByteBuffer.wrap(fci);
            long lost = (long) bb.getChar();
            ret.add(lost);
            long bits = (long) bb.getChar();
            for (int i = 0; i < 16; i++) {
                long bit = bits & 0x1;
                if (bit != 0) {
                    ret.add(lost + i + 1);
                }
                bits = bits >> 1;
            }
            return ret;
        }
    }

    public class ReportBlock {

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

        public long getSsrc() {
            return ssrc;
        }

        public int getFrac() {
            return frac;
        }

        public int getCumulost() {
            return cumulost;
        }

        public long getHighestSeqRcvd() {
            return highestSeqRcvd;
        }

        public long getIaJitter() {
            return iaJitter;
        }

        public long getLsr() {
            return lsr;
        }

        public long getDlsr() {
            return dlsr;
        }

        public String toString() {
            return "ReportBlock for ssrc=" + ssrc + " frac=" + frac + " cumulost=" + cumulost + " highestSeqRcvd=" + highestSeqRcvd + " iaJitter=" + iaJitter + " lsr=" + lsr + " dlsr=" + dlsr;
        }

        private void addBody(ByteBuffer bb) {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

    }

}
