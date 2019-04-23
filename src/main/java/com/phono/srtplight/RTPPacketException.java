/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.phono.srtplight;

import java.io.IOException;

/**
 *
 * @author thp
 */
public class RTPPacketException extends IOException {
    
    public RTPPacketException(String mess) {
        super(mess);
    }
    
}
