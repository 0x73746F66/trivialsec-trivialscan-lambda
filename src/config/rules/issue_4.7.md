The server sent a response header allows you to ensure a top-level document does not share a browsing context group with cross-origin documents.

COOP will process-isolate your document and potential attackers can't access your global object if they were to open it in a popup, preventing a set of cross-origin attacks dubbed XS-Leaks.

**Note** this feature has no impact where malicious actors have full contorl over client requests to simply ignore server response headers it does not want to process or adhere to.
