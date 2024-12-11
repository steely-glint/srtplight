package com.phono.srtplight;

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
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

public class RTPProtocolImpl extends BitUtils implements RTPProtocolFace {

    final static int RTPHEAD = 12;
    final static private int RTPVER = 2;
    final static Random _rand = new SecureRandom();
    private RTPDataSink _rtpds;
    /*  inbound state vars */
    private long _sync = -1;
    protected long _index;
    private boolean _first;
    protected long _roc = 0; // only used for inbound we _know_ the answer for outbound.
    protected char _s_l;// only used for inbound we _know_ the answer for outbound.

    /* networky stuff bidriectional*/
    DatagramSocket _ds;
    SocketAddress _far;
    protected Thread _listen;
    String _session;
    protected boolean _srtp = false;
    int _id;
    /* we don't support assymetric codec types (we could I suppose) so this is bi */
    int _ptype;

    /* outbound state */
    long _seqno;
    protected long _csrcid;
    protected int _tailIn;
    protected int _tailOut;
    private int _dtmfType = 101;
    private Exception _lastx;
    private boolean _realloc = false;
    private long[] csrc;
    private byte [] extens;
    private Character extype;

    public RTPProtocolImpl(int id, DatagramSocket ds, InetSocketAddress far, int type) {
        _ds = ds;
        _far = far;
        _id = id;
        _ptype = type;
        _session = "RTPSession" + id;
        _seqno = 0;
        _csrcid = _rand.nextInt();
        if (_ds != null) {
            try {
                if (_far != null) {
                    if (!far.getAddress().isLoopbackAddress()) {
                        _ds.connect(_far);
                    } // if we are talking to loopback we dont need the extra 
                    // security of connecting.
                }
                _ds.setSoTimeout(100);
            } catch (SocketException ex) {
                Log.warn("Problem with datagram socket:" + ex.getMessage());
            }
        } else {
            Log.verb("RTPProtocolImpl with no datagram socket");
        }

        if (_ds != null) {
            // I like to hide the run method, otherwise it is public
            Runnable ir = new Runnable() {

                public void run() {
                    irun();
                }

            };
            _listen = new Thread(ir);
            _listen.setName(_session);
        }
        _first = true;
        Log.debug("RTP session " + this.getClass().getSimpleName() + _session);
    }

    public byte [] getExtens(){
        return extens;
    }
    public Character getExtype(){
        return extype;
    }
    public void setSSRC(long v) {
        _csrcid = v;
    }

    public RTPProtocolImpl(int id, String local_media_address, int local_audio_port, String remote_media_address, int remote_audio_port, int type) throws SocketException {
        this(id, new DatagramSocket(local_audio_port), new InetSocketAddress(remote_media_address, remote_audio_port), type);
    }

    public void setRealloc(boolean v) {
        _realloc = v;
    }

    protected void irun() {
        byte[] data = new byte[1490];
        DatagramPacket dp = new DatagramPacket(data, data.length);
        Log.debug("Max Datagram size " + data.length);
        Log.debug("address is  " + _ds.getLocalSocketAddress().toString());
        long count = 0;
        while (_listen != null) {
            try {
                Log.verb("rtp loop");
                _ds.receive(dp);
                parsePacket(dp);
                count++;
                if (_realloc) {
                    data = new byte[1490];
                    dp = new DatagramPacket(data, data.length);
                }
            } catch (java.net.SocketTimeoutException x) {
                if (count > 0) {
                    Log.debug("Timeout waiting for packet");
                }
            } catch (IOException ex) {
                Log.debug(this.getClass().getSimpleName() + " " + ex.toString());
                _lastx = ex;
            }
        }
        if (!_ds.isClosed()) {
            _ds.close();
        }
        // some tidyup here....
    }

    public void setRTPDataSink(RTPDataSink ds) {
        _rtpds = ds;
    }

    public void terminate() {
        _listen = null;
    }

    static long get4ByteInt(byte[] b, int offs) {
        return ((b[offs++] << 24) | (b[offs++] << 16) | (b[offs++] << 8) | (0xff & b[offs++]));
    }

    public void sendPacket(byte[] data, long stamp, int ptype) throws SocketException, IOException {
        sendPacket(data, stamp, ptype, false);
    }

    public long getIndex() {
        return _index;
    }

    public long getSeqno() {
        return _seqno;
    }

    public Exception getNClearLastX() {
        Exception ret = _lastx;
        ret = null;
        return ret;
    }

    public void sendPacket(byte[] data, long stamp, int ptype, boolean marker) throws IOException {
        sendPacket(data, stamp, (char) _seqno, ptype, marker);
        _seqno++;
    }

    public void sendPacket(byte[] data, long stamp, char seqno, int ptype, boolean marker) throws IOException {
        // skip X
        // skip cc
        // skip M
        // all the above are zero.
        try {
            byte[] payload = new byte[RTPHEAD + data.length + _tailOut]; // assume no pad and no cssrcs
            copyBits(RTPVER, 2, payload, 0); // version
            // skip pad
            // skip X
            // skip cc
            // skip M
            // all the above are zero.
            if (marker) {
                copyBits(1, 1, payload, 8);
            }
            copyBits(ptype, 7, payload, 9);
            payload[2] = (byte) (seqno >> 8);
            payload[3] = (byte) seqno;
            payload[4] = (byte) (stamp >> 24);
            payload[5] = (byte) (stamp >> 16);
            payload[6] = (byte) (stamp >> 8);
            payload[7] = (byte) stamp;
            payload[8] = (byte) (_csrcid >> 24);
            payload[9] = (byte) (_csrcid >> 16);
            payload[10] = (byte) (_csrcid >> 8);
            payload[11] = (byte) _csrcid;
            for (int i = 0; i < data.length; i++) {
                payload[i + RTPHEAD] = data[i];
            }
            appendAuth(payload);
            sendToNetwork(payload);

            Log.verb("sending RTP " + ptype + " packet length " + payload.length + "seq =" + (int) seqno + " csrc=" + _csrcid + " stamp=" + stamp);
        } catch (IOException ex) {
            _lastx = ex;
            Log.error("Not sending RTP " + ptype + "ex = " + ex.getMessage());
            throw ex;
        }

    }

    protected void sendToNetwork(byte[] payload) throws IOException {
        DatagramPacket p = (_far == null) ? new DatagramPacket(payload, payload.length)
                : new DatagramPacket(payload, payload.length, _far);
        _ds.send(p);
    }

    protected void parsePacket(DatagramPacket dp) throws IOException {

        // parse RTP header (if we care .....)
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         */
        byte[] packet = dp.getData();
        byte[] payload;
        int plen = dp.getLength();

        int ver = 0;
        int pad = 0;
        int csrcn = 0;
        int mark = 0;
        int ptype = 0;
        char seqno = 0;
        long stamp = 0;
        int sync = 0;
        int x = 0;
        int exlen = 0;

        Log.verb("got packet " + plen);

        if (plen < 12) {
            throw new RTPPacketException("Packet too short. RTP must be >12 bytes");
        }
        ver = copyBits(packet, 0, 2);
        pad = copyBits(packet, 2, 1);
        x = copyBits(packet, 3, 1);
        csrcn = copyBits(packet, 4, 4);
        mark = copyBits(packet, 8, 1);
        ptype = copyBits(packet, 9, 7);
        ByteBuffer pb = ByteBuffer.wrap(packet);

        seqno = pb.getChar(2);
        stamp = getUnsignedInt(pb, 4);
        sync = pb.getInt(8);
        if (plen < (RTPHEAD + 4 * csrcn)) {
            throw new RTPPacketException("Packet too short. CSRN =" + csrcn + " but packet only " + plen);
        }

        csrc = new long[csrcn];
        int offs = RTPHEAD;
        for (int i = 0; i < csrcn; i++) {
            csrc[i] = getUnsignedInt(pb, offs);
            offs += 4;
        }
        if (x > 0) {
            extype = new Character(pb.getChar(offs));
            offs+=2;
            exlen = pb.getChar(offs);
            offs+=2;
            Log.verb("skip an extension 0x"+Integer.toHexString(extype)+" length "+exlen);
            extens = new byte[4*exlen];
            for (int i=0;i<extens.length;i++){
                extens[i]= packet[offs++];
            }
        } else {
            extype = null;
        }
        int endhead = offs;
        // if padding set then last byte tells you how much to skip
        int paylen = (pad == 0) ? (plen - offs) : ((plen - offs) - (0xff) & packet[plen - 1]);
        // SRTP packets have a tail auth section and potentially an MKI
        paylen -= _tailIn;
        payload = new byte[paylen];
        int o = 0;
        while (offs - endhead < paylen) {
            payload[o++] = packet[offs++];
        }
        // quick plausibility checks
        // should check the ip address etc - but actually we better trust the OS
        // since we have 'connected' this socket meaning _only_ correctly sourced packets seen here.
        // or packets from local host if that's where _far is
        if (ver != RTPVER) {
            throw new RTPPacketException("Only RTP version 2 supported");
        }
        if (ptype != _ptype) {
            throw new RTPPacketException("Unexpected payload type " + ptype);
        }
        if (sync != _sync) {
            syncChanged(sync);
        }
        _index = getIndex(seqno);
        try {
            updateCounters(seqno);
            checkAuth(packet, plen);
        } catch (RTPPacketException rpx) {
            Log.debug("Failed packet sync = " + (0 + seqno));
            Log.debug("index is = " + _index);
            if (this instanceof SRTPProtocolImpl) {
                Log.debug("roc is = " + ((SRTPProtocolImpl) this)._roc);
            }

            throw rpx;
        }
        deliverPayload(payload, stamp, sync, seqno, mark);

        Log.verb("got RTP " + ptype + " packet " + payload.length);

    }

    void checkAuth(byte[] packet, int plen) throws RTPPacketException {
    }

    long getIndex(
            char seqno) {
        long v = _roc; // default assumption

        // detect wrap(s)
        int diff = seqno - _s_l; // normally we expect this to be 1
        if (diff < Short.MIN_VALUE) {
            // large negative offset so
            v = _roc + 1; // if the old value is more than 2^15 smaller
            // then we have wrapped
        }
        if (diff > Short.MAX_VALUE) {
            // big positive offset
            v = _roc - 1; // we  wrapped recently and this is an older packet.
        }
        if (v < 0) {
            v = 0; // trap odd initial cases
        }
        /*
        if (_s_l < 32768) {
        v = ((seqno - _s_l) > 32768) ? (_roc - 1) % (1 << 32) : _roc;
        } else {
        v = ((_s_l - 32768) > seqno) ? (_roc + 1) % (1 << 32) : _roc;
        }*/
        long low = (long) seqno;
        long high = ((long) v << 16);
        long ret = low | high;
        return ret;

    }

    protected void deliverPayload(byte[] payload, long stamp, int ssrc, char seqno) {
        if (_rtpds != null) {
            _rtpds.dataPacketReceived(payload, stamp, getIndex(seqno));
        }
    }

    void appendAuth(byte[] payload, char seqno) throws RTPPacketException {
    }

    void appendAuth(byte[] payload) throws RTPPacketException {
        // nothing to do in rtp
    }

    void updateCounters(
            char seqno) {
        // note that we have seen it.
        int diff = seqno - _s_l; // normally we expect this to be 1
        if (seqno == 0) {
            Log.debug("seqno = 0 _index =" + _index + " _roc =" + _roc + " _s_l= " + (0 + _s_l) + " diff = " + diff + " mins=" + Short.MIN_VALUE);
        }
        if (diff < Short.MIN_VALUE) {
            // large negative offset so
            _roc++; // if the old value is more than 2^15 smaller
            // then we have wrapped
        }
        _s_l = seqno;
    }

    protected void syncChanged(long sync) throws RTPPacketException {
        if (_sync == -1) {
            _sync = sync;
        } else {
            throw new RTPPacketException("Sync changed: was " + _sync + " now " + sync);
        }
    }

    public static long getUnsignedInt(ByteBuffer bb, int loc) {
        return ((long) bb.getInt(loc) & 0xffffffffL);
    }

    public static void putUnsignedInt(ByteBuffer bb, long value, int loc) {
        bb.putInt(loc, (int) (value & 0xffffffffL));
    }

    public void startrecv() {
        _listen.start();
    }

    public DatagramSocket getDS() {
        return _ds;
    }

    public boolean finished() {
        return _listen == null;
    }

    public void sendDigit(String value, long stamp, int samples, int duration) throws SocketException, IOException {
        /*
        Event  encoding (decimal)
        _________________________
        0--9                0--9
         *                     10
        #                     11
        A--D              12--15
        Flash                 16
         *

        The payload format is shown in Fig. 1.

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     event     |E|R| volume    |          duration             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         */
        int sp = 0;
        int end = 0;
        int db = 3;
        char c = value.toUpperCase().charAt(0);
        if (c >= '0' && c <= '9') {
            sp = (c - '0');
        } else {
            if (c == '#') {
                sp = 11;
            }
            if (c == '*') {
                sp = 10;
            }
        }
        if ((c >= 'A') && (c <= 'D')) {
            sp = (12 + (c - 'A'));
        }
        byte data[] = new byte[4];


        /*
        data[0] = (byte) ((0xff) & (sp | 0x80)); // set End flag
        data[1] = 0 ; // 0db - LOUD
        data[3] = (byte) ((0xff) & (dur));
        data[2] = (byte) ((0xff) & (dur >> 8)) ;
         *
         */
        copyBits(sp, 8, data, 0);
        copyBits(end, 0, data, 8);
        copyBits(db, 6, data, 10);
        copyBits(samples, 16, data, 16);

        sendDTMFData(data, stamp, true);

        // try to ensure that the time between messages is slightly less than the
        // selected 'duration'
        long count = (duration / 20) - 1;
        for (int i = 0; i < count; i++) {
            try {
                Thread.sleep(10);
                sendDTMFData(data, stamp, false);// send an update
                Thread.sleep(10);

            } catch (InterruptedException ex) {
                Log.verb(ex.getMessage());
            }
        }
        //stupid ugly mess - fixed stamp on multiple packets
        //stamp = fac * _audio.getOutboundTimestamp();
        end = 1;
        copyBits(end, 1, data, 8);
        sendDTMFData(data, stamp, false);
        sendDTMFData(data, stamp, false);
        sendDTMFData(data, stamp, false);

    }

    public boolean sendDTMFData(byte[] data, long stamp, boolean mark) throws SocketException, IOException {
        boolean ret = false;
        sendPacket(data, stamp, _dtmfType, mark);
        ret = true;
        return ret;
    }

    public void setDTMFPayloadType(int type) {
        _dtmfType = type;
    }

    protected void deliverPayload(byte[] payload, long stamp, int sync, char seqno, int mark) {
        deliverPayload(payload, stamp, sync, seqno);
    }

    public static void main(String[] args) {
        // loop back test
        byte data[] = new byte[1209];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(data);
        long stamp = 0;
        int id;
        int type;
        final DatagramPacket[] dsa = new DatagramPacket[1];
        final long gstamp[] = new long[1];
        final long gindex[] = new long[1];
        try {
            DatagramSocket ds = new DatagramSocket() {
                @Override
                public void send(DatagramPacket dp) throws IOException {
                    dsa[0] = dp;
                }
            };
            id = sr.nextInt(Character.MAX_VALUE);
            type = sr.nextInt(Byte.MAX_VALUE);
            RTPProtocolImpl target = new RTPProtocolImpl(id, ds, null, type);
            RTPDataSink rtpds = new RTPDataSink() {
                @Override
                public void dataPacketReceived(byte[] data, long stamp, long index) {
                    gstamp[0] = stamp;
                    gindex[0] = index;
                }
            };
            target.setRTPDataSink(rtpds);
            while (stamp < 0x200000000L) {
                target.sendPacket(data, stamp, type);
                target.parsePacket(dsa[0]);
                if (gstamp[0] != stamp) {
                    throw new java.lang.ArithmeticException("Stamp is wrong " + gstamp[0] + " != " + stamp);
                }
                long xindex = stamp;
                if (gindex[0] != xindex) {
                    throw new java.lang.ArithmeticException("Index is wrong " + gindex[0] + " != " + xindex);
                }
                if ((stamp % 0x1000000) == 0) {
                    System.out.println("did " + stamp + " tests");
                }
                stamp++;
            }
        } catch (Exception x) {
            System.out.println("exception " + x.getLocalizedMessage());

            x.printStackTrace();
        }
        System.out.println("did " + stamp + " tests");

    }
}
