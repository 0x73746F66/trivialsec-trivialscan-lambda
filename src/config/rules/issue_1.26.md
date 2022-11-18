When a web browser reports an error that describes Version Interference (e.g. Chrome ERR_SSL_VERSION_INTERFERENCE), this indicates that the we browser on the user's system has attempted to negotiate a TLS connection with the web server using a TLS version which is not known by the web server.

This is typically seen when new TLS versions are in draft status, recently released, or an attacker in-the-middle is present and altering the TLS negotiation.

This error is widely misunderstood to be an issue with the web browser, but it is merely a symptom that appears in the web browser when the root cause of this problem exists with the web server (or introduced by an attacker).

An outdated version (or misconfigured e.g. CORS header) of web server introduces TLS Version Interference errors for which it may be possible to change web browsers entirely (or upgrade/downgrade) to avoid the issues with the web server.