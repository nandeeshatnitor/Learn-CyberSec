#!/bin/sh
# Start DocViewer inside the lab. Runs as the unprivileged lab user on a read-only root
# filesystem: everything writable lives in /lab (a small in-memory scratch area).
set -eu
mkdir -p /lab/app /lab/docs /lab/private
cp /opt/lab/app/server.py /lab/app/server.py
cp -R /opt/lab/docs/. /lab/docs/
# The platform gives every lab instance its own random secret. It is planted where the portal is
# never supposed to serve it from; only the weakness exposes it.
printf '%s\n' "${LAB_CANARY:-not-set}" > /lab/private/canary.txt
printf 'Internal only: payroll export runs on Fridays.\n' > /lab/private/notes.txt
chmod 600 /lab/private/canary.txt
unset LAB_CANARY
# Supervisor: restart the portal if it exits (for example after the student's fix is applied).
while :; do
  python /lab/app/server.py || true
  sleep 0.3
done
