# Provenance

- License: MIT, inherited from the workspace.
- Implementation: original Zray-Core code, including the bounded HTTP/TLS
  protocol sniffer used for route-only and destination-rewrite decisions.
- Upstream behavioral references: `RESEARCH-01.md` and the Xray-core oracle
  named in `PLAN-01.md`; no upstream source file is copied into this crate.
- Quarantined sources: AGPL projects under `reference/` are research-only and
  are not dependencies of this crate.
