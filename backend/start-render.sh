#!/bin/sh
# Render free tier has no pre-deploy hook: migrate on every boot (alembic is idempotent).
set -e
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers
