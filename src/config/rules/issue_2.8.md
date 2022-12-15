Continued use of weak keys in certificates puts your sensitive data at risk. Exhaustive key searches or brute force attacks against certificates with weak keys are dangerous to network security.
As computational power increases, so does the need for stronger keys.

If this is not the leaf certificate it is a root or intermediate which signs other digital certificates with its private key, if the private key is weak it may be compromised and all the rest of the issued certificates become useless.

Diffie-Hellman key exchange depends for its security on the presumed difficulty of solving the discrete logarithm problem.

By design, many Diffie-Hellman implementations use the same pre-generated prime for their field, because of the reuse of primes generating pre-computation for just one prime would expose millions of implementations. This vulnerability was known as early as 1992.

Claims on the practical implications of the attack at the time were however disputed by security researchers but over the years it is expected that many primes were and still are being calculated practically making all primes of 2048 bit or less considered weak or vulnerable.
