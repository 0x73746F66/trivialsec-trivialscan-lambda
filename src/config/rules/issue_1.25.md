The chain terminates with a Root CA Certificate. The Root CA Certificate is always signed by the CA itself. The signatures of all certificates in the chain must be verified up to the Root CA Certificate.

Each certificate in the chain is checked to ensure it is not expired and the chain path is complete.

When the root certificates are available in trust-store, this script will use its public key to verify the root certificate, once it verifies it will verify trust the intermediate certificate and eventually the server (leaf) certificate to complete the chain.

Only one valid chain from trusted root to the leaf certificate is needed to be compatible with web browsers, however the entire certificate chain should be valid to be considered trustworthy as any compromised certificate in any chain would allow malicious attackers to sign a leaf certificate which would be considered valid in the parallel chain.