### Inappropriate access control

A direct object reference occurs when a developer presents a reference to an internal application object, such as a file, directory, database record, or key, as a URL or form parameter. Attackers can change these references to access other unauthorized objects.

Access controls must be applied consistently at the application layer and business logic for all URLs. The only way for an application to protect sensitive functionality is to prevent links or URLs from being viewed by unauthorized users.

Attackers can perform unauthorized actions by directly accessing these URLs. An attacker can enumerate and navigate the directory structure of a website so that they can gain access to unauthorized information and learn more about the functioning of the site for later exploitation.

If user interfaces allow access to unauthorized functions, this access can result in unauthorized persons gaining access to privileged credentials or cardholder data. Only authorized users should be allowed to access direct object references to sensitive resources. Limiting access to data sources will help prevent cardholder data from being made available to unauthorized sources.

Unsafe direct object references in software development policies and procedures, inability to restrict URL access or inappropriate access control, such as directory traversal, should be addressed with coding techniques that include:

- Users must be properly authenticated.
- Entries should be sanitized.
- Internal object references should not be disclosed to users.
- User interfaces that do not allow access to unauthorized functions should be designed.