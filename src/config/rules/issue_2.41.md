Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authority, as it offers no security characteristics of TLS built on Trust Anchor system.

When visiting a website that uses an suspicious Certificate it is likely the TLS connection is not secure.

Conversely, if a malicious CA Root Certificate is present in the trusted stores then all website that have a leaf certificated issued by this CA will gain the ability to eaves-drop on all unencrypted information, inherently due to the nature they are providing the means for the encryption inherently and are present in the trusted CA Root store.

The original source of these root certificates is the [Common CA Database (CCADB)](https://www.ccadb.org/) (also the source for Google, Microsoft, Apple, and many more).

Then they are curated and prepared for bundling into Mozilla's Network Security Services (NSS), which is consumed by most Mozilla products and published publicly to also be consumed by countless 3rd party products.

The open source tool [mk-ca-bundle](https://curl.se/docs/mk-ca-bundle.html) creates the bundle and [further curates](https://github.com/curl/curl/blob/master/scripts/mk-ca-bundle.pl#L626) the certificates.

It doesn't appear `curl` apply bespoke filtering, and the resultant Root CA Trust Store is verifiable.
