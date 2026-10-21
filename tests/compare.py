#!/usr/bin/env python3
"""Compare two dump.php outputs (direct vs. via guard). Args: a.json b.json [ignored server keys...]"""
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
ignore = set(sys.argv[3:]) | {"SERVER_PROTOCOL", "HTTP_X_GUARD_ORIG_IP", "CONTENT_LENGTH"}
diff = []
for k in ("post", "files"):
    if a[k] != b[k]:
        diff.append(f"{k}: baseline={json.dumps(a[k], ensure_ascii=False)[:300]} guard={json.dumps(b[k], ensure_ascii=False)[:300]}")
sa = {k: v for k, v in a["server"].items() if k not in ignore}
sb = {k: v for k, v in b["server"].items() if k not in ignore}
if sa != sb:
    diff.append(f"server: baseline={sa} guard={sb}")
if diff:
    print("\n".join(diff)); sys.exit(1)
