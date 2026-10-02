#!/usr/bin/env python3
"""Split the `user_configs` workflow input into one file per configuration.

```sh
python3 split_configs.py "$RUNNER_TEMP/user-configs" <<< "$CONFIGS"
```

A `workflow_dispatch` textarea is the only way a person can hand a run their own
configurations without opening a pull request, and the thing they paste is
usually several documents at once: two configs from a panel, or a config plus a
base64 subscription. Splitting them is a parsing problem, so it lives here
rather than as a hundred lines of shell in the workflow.

The split is on a line that opens a top-level object, with brace depth tracked
so the braces inside a document do not start a new one. A pretty-printed
document and a compact one-line document both satisfy it, and a base64 body has
no braces at all, so one rule covers every shape a person actually pastes.

Written documents are byte-for-byte what the harness will measure, and they are
uploaded with the run, because a subscription that changes between two runs is
otherwise impossible to reproduce.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys


def split(text: str) -> list[str]:
    """Split where a new top-level object starts, tracking brace depth.

    The rule is "a line whose first non-space character is `{`, at depth zero",
    which covers both shapes people paste: a pretty-printed document, whose
    first line is `{`, and a compact one-line document, which is itself. Depth
    is tracked by counting *every* line including the one that opened the
    document, so a document that is already balanced on its first line closes
    immediately instead of swallowing the rest of the input.
    """
    blocks: list[str] = []
    current: list[str] = []
    depth = 0
    for line in text.splitlines():
        opens = line.count("{")
        closes = line.count("}")
        if depth == 0:
            if not line.lstrip().startswith("{"):
                # Between documents: whitespace, or a base64 subscription body.
                if current and "\n".join(current).strip():
                    blocks.append("\n".join(current))
                current = []
                continue
            current = []
        current.append(line)
        depth += opens - closes
        if depth <= 0:
            blocks.append("\n".join(current))
            current, depth = [], 0
    if current and "\n".join(current).strip():
        blocks.append("\n".join(current))
    return [b for b in (block.strip() for block in blocks) if b]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    outdir = pathlib.Path(argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    text = os.environ.get("CONFIGS", "")
    if not text.strip():
        print("the CONFIGS environment variable is empty")
        return 1

    blocks = split(text)
    # A single document that did not start at column zero, or a base64
    # subscription body, still counts. Being strict about the split rule would
    # reject a perfectly good input for a formatting reason, and deciding
    # whether an input is usable is the harness's job, not this script's: the
    # harness reports what it could not read and why.
    if not blocks:
        stripped = text.strip()
        if not stripped:
            print("nothing to write after stripping whitespace")
            return 1
        blocks = [stripped]

    written = []
    for index, body in enumerate(blocks, start=1):
        try:
            json.loads(body)
            kind = "json"
        except json.JSONDecodeError:
            kind = "not json; the harness will try a base64 subscription body"
        path = outdir / f"pasted-{index}.json"
        path.write_text(body + "\n")
        written.append(f"{path.name} ({kind}, {len(body)} bytes)")

    print(f"wrote {len(written)} configuration(s):")
    for line in written:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
