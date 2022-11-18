Server supports TLS compression which may allow CRIME/BEAST attacks.

CRIME attacks break encryption by analyzing the compression algorithm, an attacker could decrypt the source data by understanding the underlying Lossless compression algorithm to exploit known weaknesses.

Lossless data compression in SPDY and TLS/SSL (DEFLATE algorithm) finds the redundancies in the body of the data and then these redundancies are represented in a smaller fashion, this enables an attacker to derive contents by testing changes in pre-encrpted compressed data and observing where the resultant encrupted data changes therefore exposing a method to learn unknown encrypoted data leaked in the same method.

The BEAST attack is much simpler, with enough observations of alternating ciphers you can derive the initialization vector and read the encrypted Session ID. With this you can decipher (decrypt) future comminications.
