package com.phono.srtplight;

import static com.phono.srtplight.SRTPProtocolImpl.getHex;
import static com.phono.srtplight.SRTPProtocolImpl.getPepper;
import static com.phono.srtplight.SRTPSecContext.saba;
import java.io.IOException;
import java.io.StringReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Properties;
import javax.crypto.Mac;

/**
 *
 * @author tim
 */
public class SRTCPProtocolImpl {

    /**
     * some ugly assumptions here: AES_CM_128_HMAC_SHA1_80 only
     *
     * @param properties
     * @param properties0
     */
    final static int AUTHLEN = 10;
    final static int CLEARHEAD = 8;
    final static int MIKEY = 0;
    final static int INDEXLEN = 4;
    private SRTPSecContext _scOut;
    private SRTPSecContext _scIn;
    private boolean _doCrypt = true;
    private boolean _doAuth = true;
    private int _tailIn;
    private int _tailOut;
    private DatagramSocket outDs;
    private int out_index;

    public SRTCPProtocolImpl(Properties l, Properties r) {
        init(l, r);
    }

    private void init(Properties lcryptoProps, Properties rcryptoProps) {
        _scIn = _scOut = null;
        try {
            if (_doAuth || _doCrypt) {
                _scIn = new SRTCPSecContext(true);
                _scIn.parseCryptoProps(rcryptoProps);
                _tailIn = _scIn.getAuthTail();
                _scOut = new SRTCPSecContext(false);
                _scOut.parseCryptoProps(lcryptoProps);
                _tailOut = _scOut.getAuthTail();
            }
        } catch (GeneralSecurityException ex) {
            Log.error(" error in constructor " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public void sendSR(long ssrc, long ntp, long stamp, long pkts, long octs) throws IOException, GeneralSecurityException {
        RTCP.SenderReport sr = RTCP.mkSenderReport();
        sr.setNTPStamp(ntp);
        sr.setRTPStamp(stamp);
        sr.setSSRC(ssrc);
        sr.setSenderOctets(octs);
        sr.setSenderPackets(pkts);
        Log.verb("RTCP about to build " + sr);
        outbound(sr);
    }

    public void sendPLI(long ssrc) throws IOException, GeneralSecurityException {
        byte[] fci = {};
        this.sendPSFB(fci, ssrc, 1);
    }
    
    public void sendPSFB(byte fci[],long ssrc,int fmt) throws IOException, GeneralSecurityException {
        RTCP.PSFB sr = RTCP.mkPSFB();
        sr.setMssrc(ssrc);
        sr.setFmt(fmt);
        sr.setSssrc(ssrc);
        sr.setSSRC(ssrc);
        sr.setFci(fci);
        Log.info("RTCP about to build " + sr);
        outbound(sr);
    }
    
    public void sendRR() throws IOException, GeneralSecurityException {
        RTCP.ReceiverReport rr = RTCP.mkReceiverReport();
        rr.setSSRC(1L);
        Log.verb("RTCP about to build " + rr);
        outbound(rr);
    }
    private void outbound(RTCP rtcp) throws IOException, GeneralSecurityException {
        int ebl = rtcp.estimateBodyLength();
        int fpl = 4 * (ebl + 1) + 4 + this._tailOut;
        ByteBuffer bbo = ByteBuffer.allocate(fpl);
        rtcp.addBody(bbo);
        Log.verb("RTCP built " + rtcp);
        Log.verb("packet body "+getHex(bbo.array()));
        
        encrypt(bbo, out_index, (int) rtcp.ssrc);
        Log.verb("RTCP encrypted " + rtcp);
        Log.verb("packet body "+getHex(bbo.array()));
        bbo.putInt((1 << 31) | (0x7fffffff & out_index));
        Log.verb("RTCP added index " + rtcp);
        Log.verb("packet body "+getHex(bbo.array()));
        appendAuth(bbo);
        Log.verb("RTCP authed " + rtcp);
        Log.verb("packet body "+getHex(bbo.array()));
        byte[] out = bbo.array();
        sendToNetwork(out);
        Log.debug("RTCP sent " + rtcp);
        out_index++;
    }
    protected void sendToNetwork(byte[] pay) throws IOException{
        DatagramPacket p = new DatagramPacket(pay, 0, pay.length);
        if (outDs != null) {
            this.outDs.send(p);
        } else {
            Log.verb("RTCP Dummy. Wanted to send this " + getHex(p.getData()));
        }
        //Log.verb("RTCP sent " + rtcp);

    }
    /*
          0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
     |V=2|P|    RC   |   PT=SR or RR   |             length          | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     |                         SSRC of sender                        | |
   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | ~                          sender info                          ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                         report block 1                        ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                         report block 2                        ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                              ...                              ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | |V=2|P|    SC   |  PT=SDES=202  |             length            | |
   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |                          SSRC/CSRC_1                          | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                           SDES items                          ~ |
   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | ~                              ...                              ~ |
   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |E|                         SRTCP index                         | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
   | ~                     SRTCP MKI (OPTIONAL)                      ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | :                     authentication tag                        : |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   |                                                                   |
   +-- Encrypted Portion                    Authenticated Portion -----+
    
     */
    void checkAuth(byte[] packet, int plen) throws RTPPacketException {
        if (Log.getLevel() > Log.DEBUG) {
            Log.verb("auth on packet " + getHex(packet, plen));
        }
        try {
            _scIn.deriveKeys(0);

            if (_doAuth) {
                Mac hmac = _scIn.getAuthMac();

                int alen = _tailIn;
                int offs = plen - alen;
                ByteBuffer m = ByteBuffer.allocate(offs);
                m.put(packet, 0, offs);

                byte[] auth = new byte[alen];
                System.arraycopy(packet, offs, auth, 0, alen);
                int mlen = plen - alen;
                Log.verb("mess length =" + mlen);
                if (Log.getLevel() > Log.DEBUG) {
                    Log.verb("auth body " + getHex(m.array()));
                }
                ((Buffer)m).position(0);
                hmac.update(m);
                byte[] mac = hmac.doFinal();

                if (Log.getLevel() > Log.DEBUG) {
                    Log.verb("auth in   " + getHex(auth));
                }
                if (Log.getLevel() > Log.DEBUG) {
                    Log.verb("auth out  " + getHex(mac, alen));
                }

                for (int i = 0; i < alen; i++) {
                    if (auth[i] != mac[i]) {
                        throw new RTPPacketException("not authorized byte " + i + " does not match ");
                    }
                }
                Log.verb("RTCP auth ok");
            }
        } catch (GeneralSecurityException ex) {
            Log.debug("RTCP auth check failed " + ex.getMessage());
            throw new RTPPacketException("Problem checking  packet " + ex.getMessage());

        }
    }

    /**
     * calculate the outbound auth and put it at the end of the packet starting
     * at length - _tail space is already allocated
     */
    void appendAuth(ByteBuffer m) throws RTPPacketException, GeneralSecurityException {

        // strictly we might need to derive the keys here too -
        // since we might be doing auth but no crypt.
        // we don't support that so nach.
        Mac mac = _scOut.getAuthMac();
        Buffer bm = (Buffer) m;
        int top = bm.limit();
        bm.position(0);
        int authLoc = top - _tailOut;
        bm.limit(authLoc);
        mac.update(m);
        byte[] auth = mac.doFinal();
        bm.limit(top);
        bm.position(authLoc);
        m.put(auth,0,_tailOut);
        bm.position(0);
        if (Log.getLevel() > Log.DEBUG) {
            Log.verb("Authed packet " + getHex(m.array()));
        }
    }

    public RTCP[] inbound(DatagramPacket pkt) throws  InvalidRTCPPacketException, RTPPacketException, GeneralSecurityException {
        ArrayList<RTCP> rtcps = new ArrayList();
        int len = pkt.getLength();
        byte[] data = new byte[len];
        System.arraycopy(pkt.getData(), 0, data, 0, len);
        Log.verb("RTCP packet " + SRTPProtocolImpl.getHex(data));
        ByteBuffer bb = ByteBuffer.wrap(data);
        char fh = bb.getChar();
        int v = (fh & ((char) (0xc000))) >>> 14;
        int p = (fh & ((char) (0x2000))) >>> 13;
        int rc = (fh & ((char) (0x1f00))) >>> 8;
        int pt = (char) (fh & ((char) (0x00ff)));
        int length = bb.getChar();
        int ssrc = bb.getInt();

        /*
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |E|                         SRTCP index                         | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
   | ~                     SRTCP MKI (OPTIONAL)                      ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | :                     authentication tag                        : |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
         */
        int tail_len = AUTHLEN + MIKEY + INDEXLEN;
        int tail_offset = len - tail_len;
        byte[] authtag = new byte[AUTHLEN];
        byte[] mikey = new byte[MIKEY];
        Buffer bbb = (Buffer) bb;
        bbb.position(tail_offset);
        long index = bb.getInt();
        boolean encryption = (index < 0);
        index = (0x7fffffff & index);
        if (MIKEY > 0) {
            bb.get(mikey);
        }
        bb.get(authtag);
        Log.verb("Tail =" + tail_len + " index=" + index + " mkti=" + getHex(mikey) + " authtag=" + getHex(authtag) + " encryption=" + encryption);
        bbb.position(0);

        if (encryption) {
            _scIn.deriveKeys(index); // or perhaps zero ?
            this.checkAuth(data, len);
             
            bbb.position(0);
            decrypt(bb, len, tail_len, ssrc, index);
            bbb.position(0);
            while (bb.remaining() >= CLEARHEAD + tail_len) {
                Log.verb("RTCP packet starts at " + bbb.position());
                RTCP rtcp = RTCP.mkRTCP(bb);
                Log.verb("RTCP packet was: " + rtcp.toString());
                rtcps.add(rtcp);
            }
        }

        RTCP[] ret = new RTCP[rtcps.size()];
        int i = 0;
        for (RTCP rtcp : rtcps) {
            ret[i++] = rtcp;
        }
        return ret;

    }

    void decrypt(ByteBuffer pkt, int len, int tail_len, int ssrc, long index) throws GeneralSecurityException {
        int plen = len - tail_len - CLEARHEAD;
        byte[] payload = new byte[plen];
        Log.verb("pkt remains " + pkt.remaining() + " offset " + CLEARHEAD + " plen " + plen);
        for (int i = 0; i < plen; i++) {
            payload[i] = pkt.get(i + CLEARHEAD);
        }
        ByteBuffer in = ByteBuffer.wrap(payload);
        // aes likes the buffer a multiple of 32 and longer than the input.
        int pl = (((payload.length / 32) + 2) * 32);
        ByteBuffer out = ByteBuffer.allocate(pl);
        ByteBuffer pepper = getPepper(ssrc, index);
        _scIn.decipher(in, out, pepper);
        for (int i = 0; i < payload.length; i++) {
            pkt.put(i + CLEARHEAD, out.get(i));
        }
    }

    public static void main(String[] args) {
        Log.setLevel(Log.ALL);
        try {
            short[] testPacketS = {
                0x81, 0xc9, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0xd4, 0x67, 0xf8, 0x33, 0x73, 0xd7, 0xc5, 0xd8,
                0x63, 0x4f, 0x82, 0x74, 0x71, 0x0a, 0x1c, 0x01, 0x1f, 0xa4, 0xa9, 0x05, 0x33, 0x40, 0x2b, 0x67,
                0x7b, 0x88, 0x8b, 0x4e, 0x6c, 0xfe, 0x33, 0xd2, 0xdf, 0x28, 0x02, 0xd2, 0x47, 0x6f, 0x1c, 0x28,
                0x1a, 0x25, 0xc4, 0xa4, 0xf5, 0x06, 0x26, 0x9f, 0x79, 0xd7, 0x7b, 0x94, 0x77, 0xd6, 0x48, 0x30,
                0xcb, 0x31, 0xd7, 0x7a, 0x80, 0x00, 0x00, 0x1e, 0x9d, 0xa2, 0x6c, 0xf1, 0x83, 0xf1, 0x97, 0x84,
                0x7d, 0x2d};
            byte[] testpacket = saba(testPacketS);

            Properties r = new Properties();
            r.load(new StringReader("crypto-suite=AES_CM_128_HMAC_SHA1_80\nrequired=1\nkey-params=inline:IzdXQaD4zH55rctZ8O+0ip3nX+FKXmuJKgmudPej\n"));
            Properties l = new Properties();
            l.load(new StringReader("crypto-suite=AES_CM_128_HMAC_SHA1_80\nrequired=1\nkey-params=inline:rpKkWGtGVlqxzzFSaR26P+e1UAC4AduIhJSsNTOK\n"));
            SRTCPProtocolImpl testMe = new SRTCPProtocolImpl(r, r);
            DatagramPacket pkt = new DatagramPacket(testpacket, testpacket.length);
            Log.debug("----------> fake inbound packet");
            testMe.inbound(pkt);
            Log.debug("----------> verify appendAuth mechanism");
            ByteBuffer va = ByteBuffer.wrap(testpacket);
            Log.debug("Before Auth: "+getHex(va.array()));
            testMe._scOut.deriveKeys(0);
            testMe.appendAuth(va);
            Log.debug("After  Auth: "+getHex(va.array()));

            Log.debug("----------> fake outbound packet");
            testMe.out_index = 0x777777;
            testMe.sendSR(0x53535353, 1500, 0, 1, 1408);
            testMe.sendRR();

        } catch (Throwable t) {
            Log.error("Thrown " + t.getMessage());
            t.printStackTrace();
        }
    }

    public void setDS(DatagramSocket ds) {
        outDs = ds;
    }

    private void encrypt(ByteBuffer bbo, long idx, int ssrc) throws GeneralSecurityException {
        _scOut.deriveKeys(idx);
        Buffer bbbo = (Buffer) bbo;
        int pos = bbbo.position();
        int paylen = pos - CLEARHEAD;
        int pl = (((paylen / 32) + 2) * 32);
        byte[] bin = new byte[paylen];
        bbbo.position(CLEARHEAD);
        bbo.get(bin, 0, paylen);
        ByteBuffer in = ByteBuffer.wrap(bin);
        ByteBuffer out = ByteBuffer.allocate(pl);
        ByteBuffer pepper = getPepper(ssrc, idx);
        _scOut.decipher(in, out, pepper);
        bbbo.position(CLEARHEAD);
        bbo.put(out.array(),0,paylen);
        bbbo.position(pos);
    }


}
