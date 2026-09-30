#!/usr/bin/env python3
"""Network isolation probe: tries to open TCP connections and reports which ones succeeded.

Run by the platform inside a throw-away container on a lab's private network, *before* the lab
itself starts. Each argument is `host:port`. One JSON line per target is printed. It only ever
connects; it sends no data.
"""

import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 1.5


def attempt(target: str) -> dict[str, object]:
    host, _, port = target.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return {"target": target, "reachable": True, "error": None}
    except OSError as exc:
        return {"target": target, "reachable": False, "error": type(exc).__name__}


def main() -> None:
    targets = sys.argv[1:]
    with ThreadPoolExecutor(max_workers=16) as pool:
        for result in pool.map(attempt, targets):
            print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
