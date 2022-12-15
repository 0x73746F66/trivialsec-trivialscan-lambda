The server sent a response header that prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).

The default configuration when this is not sent allows the document to fetch cross-origin resources which leaves users' vulnerable to cross-site scripting (XSS) attacks.

**Note** this feature has no impact where malicious actors have full control over client requests to simply ignore server response headers it does not want to process or adhere to.
