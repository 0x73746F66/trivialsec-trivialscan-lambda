Many web servers are not fully compliant with TLS and may not properly negotiate a TLS version that both the client (web browser) and server support.
E.g. when a client advertises support for "TLS 1.3" the web server may drop the connection (not respond correctly with the TLS version it supports).

This is a common web server coding error/bug; The symptom is presented to the user in a web browser by an error message related to "we can not reach this website" (or similar).