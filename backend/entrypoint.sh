#!/bin/sh
set -eu

alembic upgrade head

if [ "${ICHECK_SEED_DATA:-false}" = "true" ]; then
  python -m icheck.seed
fi

exec uvicorn icheck.main:app --host 0.0.0.0 --port 8000

