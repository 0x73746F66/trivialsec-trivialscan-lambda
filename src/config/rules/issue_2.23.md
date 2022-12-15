Certificate Transparency (CT) is a mechanism which helps domain owners and industry watch dogs detect miss-issuance.

Miss-issuance occurs when a Certificate Authority (CA) issues an SSL certificate improperly.
This may mean that the CA included incorrect information in the certificate, issued the certificate to someone who did not represent the organisation or domain, or was even compromised.

Some browsers require certificates to have proof of being logged with certificate transparency, Safari requires up to 3 SCTs and Chrome requires between 3 and 5. The policies are far more complex than this so the generalised best practice is using at least 3 distinct SCTs per certificate.
