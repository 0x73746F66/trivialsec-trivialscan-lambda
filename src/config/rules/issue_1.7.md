A client Certificate was presented and Mutual Authentication (M/TLS) expected, if the presented client Certificate did not match the server sent subjects or the

Certificate was not issued by a trusted Root Certificate Authority this connection attempt should not be considered secure.

If a connection is established and the TLS server was miss-configured the TLS connection should be distrusted as it may be compromised, ineffetive at providing the intended security characteristics, or simply not meet the requirements for TLS which is designed to have a chain of trust that relies on Certificate issuers to follow the specification when issuing Certificates and also TLS servers configured per the specification.
