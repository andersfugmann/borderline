# Borderline

Borderline is a firewall generator for linux.
The idea is to have a simpler rule language, and an opimizing backend to
so rules can be written naively.

The firewall handles both ipv4 and ipv6 addresses

## Configuration

The idea is that the network is segmented into zones to easy specification
of rules to control traffic between zones.

Zones are usually one per interfaces, but not limited to this. Zones
are definedby a list of networks (ipv4 and ipv6) and a list of network
interfaces.

## Not handled yet

* MAC filtering
* System.d integraiton
* System settings checking (like ip_forward, log_martian)

# Installation
To be written

## Status =
Version 1.0 is very close.
The firewall handles ipv4 and ipv6 addresses and output working nft script.
