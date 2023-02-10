The Referrer-Policy HTTP header controls how much referrer information (sent with the Referrer header) should be included with requests.

This policy will leak potentially-private information from HTTPS resource URLs to insecure origins. Carefully consider the impact of this setting.

**Note** this feature has no impact where malicious actors have full control over client requests to simply ignore server response headers it does not want to process or adhere to.
