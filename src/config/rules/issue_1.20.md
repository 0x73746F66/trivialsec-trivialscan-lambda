Depending on your specific application, and how important the history of your network interaction may be, you may want to forego TLS session resumption altogether.

Long session gaps can give bad actors time to hack into a session and cause trouble. This is why session IDs and session tickets both have security timeout settings that are dictated by the server. When an ID or a ticket expires, the server intentionally flushes cached session data and forces a complete new session handshake when the client initiates the next contact.

Leaking any information for attackers to derive ways to weaken TLS results in ineffective data protection or broken integrity of communications.