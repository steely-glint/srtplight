# srtplight
## set of classes implementing a simple (S)RTP stack
 - In pure Java. 
 - Acceptably quick as the JVM offloads AES to hardware when possible (eg on ARM)
 - Supports RTP, SRTP and (S)RTCP 
 - SRTP in AES_CM_128_HMAC_SHA1_80 only
 - Tested against all the major browser webRTC implementations 
 - Does _not_ include WebRTC's DTLS-SRTP key exchange (look at BouncyCastle for that)
 ## It was originally written for Voxeo's Phono project as part of an applet based in-browser phone.
 - issues,PRs,fixes etc are welcome
 - Apache license.
 - now used in |pipe| (see github.com/pipe/)

## See also a minimal webRTC implemenation
https://github.com/pipe/whipi
based on this library, BouncyCastle and 
https://github.com/steely-glint/slice




