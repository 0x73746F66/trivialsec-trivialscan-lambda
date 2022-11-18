The security benefit characteristics of OCSP can only be enforced when the 'Must Staple' flag is present.

Failing to include the must staple extension in a Domain Validated (DV) or Organisation Validated (OV) Certificate will allow most web browsers and HTTP clients to 'soft-fail' the OCSP check and continue with TLS without an OCSP assertion or knowledge of revocation status.

In some web browsers and HTTP clients an Extended Validation (EV) certificate will hard-fail when an OCSP assertion is not obtained, but this functionality should not be relied upon as there have been many changes made by web browsers that are divergent from standards and break assumed security guarantees suddenly become a vulnerability.

Everywhere the OCSP Must Staple Extension is accepted, it will be enforced for all certificates regardless of validation semantics.