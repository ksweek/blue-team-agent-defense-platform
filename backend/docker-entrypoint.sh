#!/bin/sh
set -eu

log() {
  printf '[docker-entrypoint] %s\n' "$*"
}

wait_for_db() {
  if [ "${WAIT_FOR_DB:-true}" = "false" ]; then
    return 0
  fi

  timeout="${DB_WAIT_TIMEOUT_SECONDS:-90}"
  interval="${DB_WAIT_INTERVAL_SECONDS:-2}"
  deadline=$(( $(date +%s) + timeout ))

  while :; do
    if python scripts/init_db.py --mode validate >/tmp/db-ready.log 2>&1; then
      return 0
    fi

    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      log "database did not become reachable within ${timeout}s"
      cat /tmp/db-ready.log >&2 || true
      return 1
    fi

    log "waiting for database to become reachable"
    sleep "$interval"
  done
}

role="${1:-${APP_ROLE:-api}}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$role" in
  init)
    wait_for_db
    exec python scripts/init_db.py --mode "${INIT_DB_MODE:-schema}"
    ;;
  api)
    wait_for_db
    if [ "$#" -gt 0 ]; then
      exec "$@"
    fi
    exec uvicorn app.main:app --host "${UVICORN_HOST:-0.0.0.0}" --port "${UVICORN_PORT:-8000}"
    ;;
  worker)
    wait_for_db
    if [ "$#" -gt 0 ]; then
      exec "$@"
    fi
    exec python run_worker.py
    ;;
  command)
    exec "$@"
    ;;
  *)
    exec "$role" "$@"
    ;;
esac
