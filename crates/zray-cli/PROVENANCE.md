# Provenance

- License: MIT, inherited from the workspace.
- Implementation: original command-line wrapper and diagnostics.
- It depends only on workspace crates and does not include quarantined
  reference code.
- The run path compiles a validated `RuntimeGeneration` before starting the
  server, matching the management reload boundary.
