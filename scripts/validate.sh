#!/usr/bin/env sh
set -eu

BACKEND_ONLY=0
FRONTEND_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --backend-only)
      BACKEND_ONLY=1
      ;;
    --frontend-only)
      FRONTEND_ONLY=1
      ;;
    *)
      echo "Unsupported argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [ "$BACKEND_ONLY" -eq 1 ] && [ "$FRONTEND_ONLY" -eq 1 ]; then
  echo "Cannot use --backend-only and --frontend-only together." >&2
  exit 1
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

run_step() {
  echo
  echo "==> $1"
  shift
  "$@"
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT_DIR"

require_command python

if [ "$FRONTEND_ONLY" -ne 1 ]; then
  run_step "Backend compile check" \
    python -m compileall backend/app backend/run_dev.py backend/run_worker.py backend/scripts/init_db.py smoke_test.py test_ai_provider.py

  run_step "Backend database validation" \
    python backend/scripts/init_db.py --mode validate
fi

if [ "$BACKEND_ONLY" -ne 1 ]; then
  require_command npm
  echo
  echo "==> Frontend production build"
  (
    cd frontend
    npm run build
  )
fi

echo
echo "Validation completed."
