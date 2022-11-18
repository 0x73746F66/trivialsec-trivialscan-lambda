Buffer overflows; attackers can be used to do all kinds of operations if appropriate border controls are not applied. When this happens, the attacker will have the ability to add malicious code to the end of the buffer and then push the malicious code into executable memory space by overflowing the buffer. The malicious code is then run and usually allows the attacker remote access to the application or the infected system.

To avoid buffer overflows, encoding techniques including:

- Appropriate boundary controls should be implemented.
- Input data must be truncated accordingly.