### Create a firewall and router configuration that restricts connections between untrusted networks and all system components in the cardholder data environment

Build firewall and router configurations that restrict connections between untrusted networks and any system components in the cardholder data environment.
Note: An “untrusted network” is any network that is external to the networks belonging to the entity under review, and/or which is out of the entity's ability to control or manage.

Examine firewall and router configurations and perform the following to verify that connections are restricted between untrusted networks and system components in the
cardholder data environment:

**1.2.1** Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment, and specifically deny all
other traffic.

Examine firewall and router configuration standards to verify that they identify inbound and outbound traffic necessary for the cardholder data environment.
Examine firewall and router configurations to verify that inbound and outbound traffic is limited to that which is necessary for the cardholder data environment.
Examine firewall and router configurations to verify that all other inbound and outbound traffic is specifically denied, for example by using an explicit “deny all” or an implicit deny after allow statement.

**1.2.2** Secure and synchronize router configuration files.
Examine router configuration files to verify they are secured from unauthorized access.
Examine router configurations to verify they are synchronized - for example, the running (or active) configuration matches the start-up configuration (used when machines are booted).

**1.2.3** Install perimeter firewalls between all wireless networks and the cardholder data environment, and configure these firewalls to deny or, if traffic is necessary for business purposes, permit only authorized traffic between the wireless environment and the cardholder data environment. Examine firewall and router configurations to verify that there are perimeter firewalls installed between all wireless networks and the cardholder data environment.
Verify that the firewalls deny or, if traffic is necessary for business purposes, permit only authorized traffic between the wireless environment and the cardholder data environment.
