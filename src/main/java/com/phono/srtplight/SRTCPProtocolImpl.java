package com.phono.srtplight;

import static com.phono.srtplight.SRTPProtocolImpl.getHex;
import static com.phono.srtplight.SRTPProtocolImpl.getPepper;
import static com.phono.srtplight.SRTPSecContext.saba;
import java.io.Reader;
import java.io.StringReader;
import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    void checkAuth(byte[] packet, int plen) throws RTPProtocolImpl.RTPPacketException {
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
                m.position(0);
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
                        throw new RTPProtocolImpl.RTPPacketException("not authorized byte " + i + " does not match ");
                    }
                }
                Log.debug("RTCP auth ok");
            }
        } catch (GeneralSecurityException ex) {
            Log.debug("RTCP auth check failed " + ex.getMessage());
            throw new RTPProtocolImpl.RTPPacketException("Problem checking  packet " + ex.getMessage());

        }
    }

    public RTCP[] inbound(DatagramPacket pkt) throws GeneralSecurityException, InvalidRTCPPacketException {
        ArrayList<RTCP> rtcps = new ArrayList();
        int len = pkt.getLength();
        byte[] data = new byte[len];
        System.arraycopy(pkt.getData(), 0, data, 0, len);
        Log.debug("RTCP packet " + SRTPProtocolImpl.getHex(data));
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
        bb.position(tail_offset);
        long index = bb.getInt();
        boolean encryption = (index < 0);
        index = (0x7fffffff & index);
        if (MIKEY > 0) {
            bb.get(mikey);
        }
        bb.get(authtag);
        Log.debug("Tail =" + tail_len + " index=" + index + " mkti=" + getHex(mikey) + " authtag=" + getHex(authtag) + " encryption=" + encryption);
        bb.position(0);

        if (encryption) {
            _scIn.deriveKeys(index); // or perhaps zero ?
            try {
                this.checkAuth(data, len);
            } catch (RTPProtocolImpl.RTPPacketException ex) {
                throw new GeneralSecurityException("Can't check auth...");
            }
            bb.position(0);
            decrypt(bb, len, tail_len, ssrc, index);
            bb.position(0);
            while (bb.remaining() >= CLEARHEAD+tail_len) {
                Log.debug("RTCP packet starts at "+bb.position());
                RTCP rtcp = RTCP.mkRTCP(bb);
                Log.debug("RTCP packet was: "+rtcp.toString());
                rtcps.add(rtcp);
            }
        }

        RTCP[] ret = new RTCP[rtcps.size()];
        int i=0;
        for (RTCP rtcp:rtcps){
            ret[i++]= rtcp;
        }
        return ret;

    }

    void decrypt(ByteBuffer pkt, int len, int tail_len, int ssrc, long index) throws GeneralSecurityException {
        int plen = len - tail_len - CLEARHEAD;
        byte[] payload = new byte[plen];
        Log.verb("pkt remains "+pkt.remaining()+" offset "+CLEARHEAD+" plen "+plen);
        for (int i=0;i<plen;i++){
            payload [i] = pkt.get(i+CLEARHEAD);
        }
        ByteBuffer in = ByteBuffer.wrap(payload);
        // aes likes the buffer a multiple of 32 and longer than the input.
        int pl = (((payload.length / 32) + 2) * 32);
        ByteBuffer out = ByteBuffer.allocate(pl);
        ByteBuffer pepper = getPepper(ssrc, index);
        _scIn.decipher(in, out, pepper);
        for (int i=0;i<payload.length;i++){
            pkt.put(i+CLEARHEAD, out.get(i));
        }
    }

    public static void main(String[] args) {
        Log.setLevel(Log.ALL);
        try {
            short[] testPacketS = {
                0x81,0xc9,0x00,0x07,0x00,0x00,0x00,0x01,0xd4,0x67,0xf8,0x33,0x73,0xd7,0xc5,0xd8,
                0x63,0x4f,0x82,0x74,0x71,0x0a,0x1c,0x01,0x1f,0xa4,0xa9,0x05,0x33,0x40,0x2b,0x67,
                0x7b,0x88,0x8b,0x4e,0x6c,0xfe,0x33,0xd2,0xdf,0x28,0x02,0xd2,0x47,0x6f,0x1c,0x28,
                0x1a,0x25,0xc4,0xa4,0xf5,0x06,0x26,0x9f,0x79,0xd7,0x7b,0x94,0x77,0xd6,0x48,0x30,
                0xcb,0x31,0xd7,0x7a,0x80,0x00,0x00,0x1e,0x9d,0xa2,0x6c,0xf1,0x83,0xf1,0x97,0x84,
                0x7d,0x2d};
            byte [] testpacket = saba(testPacketS);

            Properties r = new Properties();
            r.load(new StringReader("crypto-suite=AES_CM_128_HMAC_SHA1_80\nrequired=1\nkey-params=inline:IzdXQaD4zH55rctZ8O+0ip3nX+FKXmuJKgmudPej\n"));
            Properties l = new Properties();
            l.load(new StringReader("crypto-suite=AES_CM_128_HMAC_SHA1_80\nrequired=1\nkey-params=inline:rpKkWGtGVlqxzzFSaR26P+e1UAC4AduIhJSsNTOK\n"));
            SRTCPProtocolImpl testMe = new SRTCPProtocolImpl(l, r);
            DatagramPacket pkt = new DatagramPacket(testpacket,testpacket.length);
            testMe.inbound(pkt);

        } catch (Throwable t) {
            Log.error("Thrown " + t.getMessage());
            t.printStackTrace();
        }
    }

}
