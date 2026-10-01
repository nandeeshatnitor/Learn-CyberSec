#!/usr/bin/env python3
"""Create a reviewer token for the candidate-lab review interface.

    python scripts/admin_token.py alice

Prints the token (give it to the reviewer once; they paste it into the sign-in page) and the
`ADMIN_REVIEWERS` entry to add to the backend's environment. Only the SHA-256 hash is ever stored
by the platform, so a lost token cannot be recovered: make a new one.
"""

import hashlib
import re
import secrets
import sys


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", sys.argv[1]):
        print("usage: admin_token.py <reviewer-name>   (letters, digits, . _ -)", file=sys.stderr)
        return 2
    name = sys.argv[1]
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"Reviewer:  {name}")
    print(f"Token:     {token}")
    print()
    print("Add to the backend environment (comma-separate several reviewers):")
    print(f"ADMIN_REVIEWERS={name}={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
