This is specifically for evaluating if the TLS connection only offers allowed cipher suites.

The FIPS 140-2 states that approved security function is either specified in the list of approved functions (which is Annex A), or specified in a Federal Information Processing Standard (FIPS).

FIPS 140-2 Implementation Guide states that DES (formally DEA) is not approved since May 19, 2007, however note the list of FIPS-140 validated modules I can see that DES is listed only in other algorithms section.

Triple-DES or 3DES (formally TDEA, not single DES or DEA) was reissued as a special publication (SP800-67) and that SP is referenced by 140-2 IG and 140-2 Annex A.
