DSA keys, and RSA keys smaller than 1024 bits offer no security and should not be used at all, whether they are known to be compromised or not.

The pwnedkeys database keeps records of compromised 1024 bit and larger RSA/DSA keys, as well as elliptic-curve keys on the P-256, P-384, and P-521 curves.

If your private key is ever compromised, it should be considered an emergency, and your priority should be resolving the issue immediately. If an unauthorised person gains access to your private key, they can assume the identity that your certificate is intended to protect (e.g. you, your company, and/or your website)
