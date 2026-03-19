# VPN Core

This directory contains the embedded VPN core used by `tuncat`.

- Upstream lineage: adapted from an upstream OpenConnect client implementation
- Runtime model: in-process core, no external VPN binaries required
- Scope: authentication, tunnel setup, DTLS/TLS channels, TUN I/O, routes, DNS, and session control

The `tuncat` CLI in `internal/app` is the only supported user-facing entrypoint.
