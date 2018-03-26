/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.phono.srtplight;

import java.security.GeneralSecurityException;

/**
 *
 * @author tim
 */
class SRTCPSecContext extends SRTPSecContext {

    public SRTCPSecContext(boolean b) {
    }

    /*
    4.3.2.  SRTCP Key Derivation

   SRTCP SHALL by default use the same master key (and master salt) as
   SRTP.  To do this securely, the following changes SHALL be done to
   the definitions in Section 4.3.1 when applying session key derivation
   for SRTCP.

   Replace the SRTP index by the 32-bit quantity: 0 || SRTCP index
   (i.e., excluding the E-bit, replacing it with a fixed 0-bit), and use
   <label> = 0x03 for the SRTCP encryption key, <label> = 0x04 for the
   SRTCP authentication key, and, <label> = 0x05 for the SRTCP salting
   key.
     */
    protected void deriveKeys(long index, int kdr) throws GeneralSecurityException {
        deriveKeys(index, kdr, 3, 5, 4);
    }

}
