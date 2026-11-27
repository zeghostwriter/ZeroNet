# Provenance

- License: MIT, inherited from the workspace.
- Implementation: original compiled matcher/router code.
- Behavioral references: Xray routing semantics and the geodata safety rules
  in `PLAN-01.md`; no upstream source file is copied into this crate.
- The environment loader accepts both the documented line format and the
  Xray geosite.dat/geoip.dat protobuf containers through a bounded local
  decoder; the compiled hot path remains independent of the container format.
