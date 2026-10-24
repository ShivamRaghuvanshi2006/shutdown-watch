# Project report notes

## Problem
Government-ordered shutdowns (mobile data, sometimes broadband) are a common response to protests in India. Affected people cannot easily show *what* was blocked or *how*. Networking gives vocabulary and tools for that.

## Concepts used
- **Layered model (OSI/TCP-IP)**: the detector isolates failures per layer.
- **DNS (UDP/53)**: we build and parse packets by hand, including name compression pointers.
- **TCP handshake and TLS/SNI**: where filtering boxes can inject resets or drop packets.
- **Delay-tolerant networking / epidemic routing**: store-carry-forward when no end-to-end path exists.

## Method
1. Resolve each target with the OS resolver and with a control resolver.
2. Connect, handshake, request; record timings and exception types.
3. `classify()` maps the first failing layer to a verdict. `summarize()` flags network-wide outage.
4. Separately, simulate mobile nodes and compare routing strategies over a fixed seed.

## Results to include (run these yourself)
- Output of `scan` on your own network, saved as `results.json`.
- Table of `mesh` runs across node counts (10, 20, 30, 50) and radii.

## Ethics
Only lawful public sites are probed, requests are single HEADs, and the user agent is identifiable. Nothing here helps bypass laws; it measures and explains.

## Future work
Multiple vantage points, IPv6, DNS-over-HTTPS control, TTL-limited and spray-and-wait routing, import of public shutdown trackers for comparison.
