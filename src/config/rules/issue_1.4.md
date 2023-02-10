If the Certificate being used for client Authentication (M/TLS) was not issued for that purpose then most properly configured servers will drop the connection.

If either the client Certificate or TLS server is miss-configured the TLS connection should be distrusted as it may be compromised, ineffective at providing the intended security characteristics, or simply not meet the requirements for TLS which is designed to have a chain of trust that relies on Certificate issuers to follow the specification when issuing Certificates and also TLS servers configured per the specification.
