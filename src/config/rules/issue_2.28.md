Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authority, as it offers no security characteristics of TLS built on Trust Anchor system.

When visiting a website that uses an suspicious Certificate it is likely the TLS connection is not secure.

Conversely, if a malicious CA Root Certificate is present in the trusted stores then all website that have a leaf certificated issued by this CA will gain the ability to eaves-drop on all unencrypted information, inherently due to the nature they are providing the means for the encryption inherently and are present in the trusted CA Root store.
