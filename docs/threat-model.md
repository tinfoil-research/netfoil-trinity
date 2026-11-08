# Threat Model

## netfoil-hi
In scope:
 - It should only be possible to send specific HTTP requests through netfoil-hi, with filtering on the whole request, including host, path, headers, verb, query parameters, and body.
 - It should not be possible to send data through netfoil-hi that is easy to retrieve by an attacker that does not control the receiving host.
 - It should not be possible to read the memory of the netfoil process. This includes secrets and the data of other requests.
 - It should not be possible to get arbitrary code execution in the netfoil-hi process or escape to the host.
 - While denial of service issues are in scope, they are not a priority.

Out of scope:
 - Netfilter or similar must be configured elsewhere to force relevant traffic through netfoil-hi and block other traffic.
 - The generic rules since they are too coarse grained.