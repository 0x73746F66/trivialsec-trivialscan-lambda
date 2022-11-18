The server sent a response header to inform supporting browsers that the MIME types advertised in the Content-Type headers should be followed and not be changed. The header allows you to avoid MIME type sniffing by saying that the MIME types are deliberately configured.

**Note** this feature has no impact where malicious actors have full contorl over client requests to simply ignore server response headers it does not want to process or adhere to.
