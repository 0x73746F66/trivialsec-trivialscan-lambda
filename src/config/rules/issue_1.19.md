The TLS session cache fails to reliably prevent resumption of an unauthenticated session, which allows remote attackers (such as malicious 802.1X supplicants) to bypass authentication for various software depending on their implementation configurations.

Other issues arise when TLS session resumption is enabled and a client certificate is used, subsequent connection attempts to the same server get a previously authenticated session 'resumed' without actually Authenticating with their own client Certificate.
