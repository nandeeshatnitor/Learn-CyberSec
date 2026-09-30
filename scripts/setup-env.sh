#!/usr/bin/env bash
# Create .env from .env.example with freshly generated random passwords.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -e .env ]]; then
  echo ".env already exists; leaving it untouched." >&2
  exit 0
fi

random_secret() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }

password="$(random_secret)"
redis_password="$(random_secret)"

# POSTGRES_PASSWORD appears in DATABASE_URL, REDIS_PASSWORD in REDIS_URL.
sed \
  -e "s#^POSTGRES_PASSWORD=change_me#POSTGRES_PASSWORD=${password}#" \
  -e "s#^REDIS_PASSWORD=change_me#REDIS_PASSWORD=${redis_password}#" \
  -e "s#^\(DATABASE_URL=.*cvelearn:\)change_me@#\1${password}@#" \
  -e "s#^\(REDIS_URL=redis://:\)change_me@#\1${redis_password}@#" \
  .env.example > .env
chmod 600 .env
echo "Created .env with generated passwords."
