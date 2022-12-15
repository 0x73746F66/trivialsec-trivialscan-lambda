The server sent a response header `Content-Security-Policy` to inform 'supporting browsers; to ensure TLS is used even when miss-configured scripts attempt insecure connections.

A supporting browser must indicate in the client request a header of `Upgrade-Insecure-Requests` with the value `1`, e.g.

```
GET / HTTP/1.1
Host: trivialsec.com
Upgrade-Insecure-Requests: 1
```

**Note** this feature has no impact to malicious clients that control the client request and avoid producing the request header (indicating it will not support the feature). This is also not going to impact a scenario where malicious actors have full control over client requests to simply ignore server response headers it does not want to process or adhere to.
