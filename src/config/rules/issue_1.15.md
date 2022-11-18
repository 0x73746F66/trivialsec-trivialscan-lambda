If the Client Hello messages longer than 255 bytes and the connection fails, this is an indication of very old web servers or a webserver with coding errors/bugs.

Using all possible valid ciphers (sending approx 3458 bytes) the 'Client Hello' will be sufficiently long to trigger this web server bug (if it exists).

This may be experienced during server to server communications over TLS, but is uncommon scenario for web browsers (that affect end users).