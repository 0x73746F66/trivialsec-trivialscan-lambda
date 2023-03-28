If disk-level or partition-level encryption is used (rather than file-, column-, or field--level database encryption) to render PAN unreadable, it is managed as follows:

- Logical access is managed separately and independently of native operating system authentication and access control mechanisms.
- Decryption keys are not associated with user accounts.
- Authentication factors (passwords, passphrases, or cryptographic keys) that allow access to unencrypted data are stored securely.
