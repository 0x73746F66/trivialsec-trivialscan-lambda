Using anything other than 65537 as the public exponent would effect compatibility with most hardware and software.

Lower isn't vulnerable with proper padding however RSA implementations are widely flawed and did not consider this security characteristic therefore in practice any low exponent could indicate weakness known to be exploited by many heavily scrutinised researchers publications.

Using exactly 65537 is an industry standard prescribed by certification authorities and compliance such as PCI DSS, Annex B.3 of FIP186-4, NIST Special Publication on Computer Security (SP 800-78 Rev. 1 of August 2007) does not allow public exponents e smaller than 65537.
