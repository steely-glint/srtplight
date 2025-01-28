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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author tim
 */
public class CCFB {
    final public static int FMT = 11; 
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |V=2|P| FMT=11  |   PT = 205    |          length               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 SSRC of RTCP packet sender                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   SSRC of 1st RTP Stream                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          begin_seq            |          num_reports          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |R|ECN|  Arrival time offset    | ...                           .
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  .                                                               .
  .                                                               .
  .                                                               .
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   SSRC of nth RTP Stream                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          begin_seq            |          num_reports          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |R|ECN|  Arrival time offset    | ...                           |
  .                                                               .
  .                                                               .
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Report Timestamp (32 bits)                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    class CCFBReport {
        final boolean recvd;
        final int ecn;
        final long timeOffset;
        
        CCFBReport(char c){
            recvd = (c & 0x8000) != 0;
            ecn = (c & 0x6000) >> 13;
            timeOffset = c & 0x3fff;
        }
        @Override
        public String toString(){
            return "recvd ="+recvd+" ecn="+ecn+" timeOffset="+timeOffset;
        }
    }
    class CCFBStream{
        final long ssrc;
        final char seq;
        final CCFBReport[] reports;
        CCFBStream(long ssrc,char beginSeq,CCFBReport reports[]){
            this.reports = reports;
            this.seq=beginSeq;
            this.ssrc = ssrc;
        }
        public String toString(){
            var reps =new StringBuffer();
            for(var r:reports){reps.append(r.toString()).append("\n\t");}
            return "ssrc="+ssrc+" seq="+(0+seq)+" reports "+reps;
        }
    }
    List<CCFBStream> streams;
    final long reportTime;
    
    public CCFB(long ssrc1, byte [] fci){
        streams = new ArrayList<>();
        ByteBuffer bb = ByteBuffer.wrap(fci);
        long s = ssrc1;
        while (bb.hasRemaining()){
            var beginSeq = bb.getChar();
            var nreps = bb.getChar();
            var rs = new CCFBReport[nreps];
            for (int n=0; n< nreps;n++){
                char v = bb.getChar();
                rs[n] = new CCFBReport(v);
            }
            if ((nreps %2)== 1){
                bb.getChar();
            }
            streams.add(new CCFBStream(s,beginSeq,rs));
            s = bb.getInt();
        }
        reportTime = s;
    }

    @Override
    public String toString(){
        StringBuffer srs = new StringBuffer();
        streams.stream().forEach((s)-> srs.append(s.toString()).append("\n"));
        return "CCFB at "+reportTime+" contains "+srs;
    }
 

}
