
The tor network here is a simplified implementation of an example, which implements a minimal version of tor's basic functions.
But this does not mean that we have modified the mechanism of tor, but only implemented part of the functions of tor.
Next, we will introduce which features of Tor we support and which parts we have simplified.

Simplified part: 
1. We assume that all simulation nodes use the v4 protocol.
Simplified the parameters in the node descriptor, retaining only the router name, IP, port, bandwidth, and uptime


Implementation content: 
1. Tor's onion routing process