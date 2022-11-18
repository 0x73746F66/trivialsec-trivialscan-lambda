Certificate authorities implementing CAA perform a DNS lookup for CAA resource records, and if any are found, ensure that they are listed as an authorized party before issuing a digital certificate.

Third parties monitoring certificate authority behavior might check newly issued certificates against the domain's CAA records. RFC 8659 states; CAA records MAY be used by Certificate Evaluators as a possible indicator of a security policy violation. Such use SHOULD take into account the possibility that published CAA records changed between the time a certificate was issued and the time at which the certificate was observed by the Certificate Evaluator.

The CAA records can help with the enforcement of your corporate policies on approved CAs. By aligning the CAA records with the list of corporate approved CAs, the risk of non-compliance to the policy is minimized.

If CAA records exist but do not include an approved or preferred CA for a specific domain, the issuance of certificates by that CA to the domain cannot proceed until the creation of the appropriate CAA record is completed.