### Restrict direct global access to any system component of the cardholder data medium over the internet

Prohibit direct public access between the Internet and any system component in the cardholder data environment.

Examine firewall and router configurations—including but not limited to the choke router at the Internet, the DMZ router and firewall, the DMZ cardholder segment, the
perimeter router, and the internal cardholder network segment—and perform the following to determine that there is no direct access between the Internet and system
components in the internal cardholder network segment:

**1.3.1** Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports. Examine firewall and router configurations to verify that a DMZ is implemented to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

**1.3.2** Limit inbound Internet traffic to IP addresses within the DMZ.
Examine firewall and router configurations to verify that inbound Internet traffic is limited to IP addresses within the DMZ.

**1.3.3** Implement anti-spoofing measures to detect and block forged source IP addresses from entering the network.

> (For example, block traffic originating from the Internet with an internal source address)

Examine firewall and router configurations to verify that anti-spoofing measures are implemented, for example internal addresses cannot pass from the Internet into the DMZ.

**1.3.4** Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet.
Examine firewall and router configurations to verify that outbound traffic from the cardholder data environment to the Internet is explicitly authorized.

**1.3.5** Permit only “established” connections into the network.
Examine firewall and router configurations to verify that the firewall permits only established connections into internal network, and denies any inbound connections not associated with a previously established session.

**1.3.6** Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the
DMZ and other untrusted networks. Examine firewall and router configurations to verify that system components that store cardholder data are on an internal network zone, segregated from the DMZ and other untrusted networks.

**1.3.7** Do not disclose private IP addresses and routing information to unauthorized parties.
**Note**: Methods to obscure IP addressing may include, but are not limited to:

- Network Address Translation (NAT),
- lacing servers containing cardholder data behind proxy servers/firewalls,
- Removal or filtering of route advertisements for private networks that employ registered addressing,
- Internal use of RFC1918 address space instead of registered addresses.

Examine firewall and router configurations to verify that methods are in place to prevent the disclosure of private IP addresses and routing information from internal networks to the Internet.
Interview personnel and examine documentation to verify that any disclosure of private IP addresses and routing information to external entities is authorized.
