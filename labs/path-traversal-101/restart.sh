#!/bin/sh
# Restart DocViewer so that a change to /lab/app/server.py takes effect. The supervisor loop in
# start.sh brings it straight back up. (The [.] keeps this script from matching itself.)
pkill -f 'python /lab/app/server[.]py' || true
