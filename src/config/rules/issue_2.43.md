Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authority, as it offers no security characteristics of TLS built on Trust Anchor system.

When visiting a website that uses an suspicious Certificate it is likely the TLS connection is not secure.

Conversely, if a malicious CA Root Certificate is present in the trusted stores then all website that have a leaf certificated issued by this CA will gain the ability to eaves-drop on all unencrypted information, inherently due to the nature they are providing the means for the encryption inherently and are present in the trusted CA Root store.

The `rustls` crate contains _curated_ root certificates for use with the `webpki` crate and anywhere `rustls` itself is used.

The original source of these root certificates is the [Common CA Database (CCADB)](https://www.ccadb.org/) (also the source for Google, Microsoft, Apple, and many more).

Then they are curated and prepared for bundling into Mozilla's Network Security Services (NSS), which is consumed by most Mozilla products and published publicly to also be consumed by countless 3rd party products.

Before `rustls` get's the bundle the [mkcert.org](mkcert.org) (commonly mistakenly referred to as the "Mozilla tooling", which it is not) further curates the certificates and serves them over a HTTP API which is insecure, as it is unverifiable what the code is doing (an open source repo is not the same as the running environment, merely a small portion is the code), but that is the method `rustls` implemented to initially get the root certificates.

Finally, `rustls` apply filtering on the subject and produce the resultant Root CA Trust Store.

**Critical Review**;
A GitHub.com issue [#25](https://github.com/rustls/webpki-roots/issues/25) outlines a lack of trust and we hope to have this addressed.
