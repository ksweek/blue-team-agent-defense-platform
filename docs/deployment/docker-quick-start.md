# Docker One-Click Deployment

This project now supports a first-class Docker startup path built around a one-shot
database init container, Redis cache, and long-running API/frontend services.

## Quick Start

1. Prepare `.env`.

```powershell
Copy-Item .env.example .env
```

2. For a demo deployment, keep the default values in `.env` and start:

```powershell
docker compose up -d --build
```

3. Open the services:

- Frontend: `http://127.0.0.1:5173`
- Backend: `http://127.0.0.1:8000`
- OpenAPI: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`

You can also use the wrapper:

```powershell
.\start.ps1 -Mode docker -Build
```

The wrapper now waits until both backend and frontend are actually reachable.

## What Starts

`docker compose up -d` now starts:

- `postgres`: persistent PostgreSQL
- `redis`: cache and short-lived gateway/runtime state
- `init`: one-shot schema/bootstrap initializer
- `backend`: FastAPI API + embedded worker by default
- `frontend`: built Vue frontend behind Nginx

## Default Behavior

- `INIT_DB_MODE=schema` keeps bootstrap idempotent and safe for repeated starts.
- `CACHE_BACKEND=redis` uses Redis first and falls back to in-memory cache if Redis is unavailable.
- In `development`, the backend can still seed demo data on first runtime start if
  `SEED_SAMPLE_DATA=true`.
- In `production`, set `BOOTSTRAP_MODE=validate` and `SEED_SAMPLE_DATA=false`.

## Production Minimum

Before production deployment, replace these values in `.env`:

- `APP_ENV=production`
- `BOOTSTRAP_MODE=validate`
- `SEED_SAMPLE_DATA=false`
- `JWT_SECRET`
- `GATEWAY_API_TOKEN`
- `BOOTSTRAP_ADMIN_PASSWORD`
- `BOOTSTRAP_ANALYST_PASSWORD`
- `DATABASE_URL` if you are not using the bundled PostgreSQL service
- `REDIS_URL` if you are not using the bundled Redis service

The API and worker will refuse unsafe production defaults.

For high-concurrency gateway, runtime, or sample-regression testing, use PostgreSQL
and Redis. The local SQLite mode is intended for development and can hit write locks
under heavy concurrent task creation.

## Optional External Worker

The default one-click path uses the embedded worker inside `backend`.

If you want a separate worker container:

```powershell
docker compose --profile external-worker up -d --build
```

Set this in `.env` at the same time:

```env
TASK_WORKER_EMBEDDED=false
```

## Useful Commands

Start or refresh:

```powershell
docker compose up -d --build
```

View status:

```powershell
docker compose ps
```

View logs:

```powershell
docker compose logs -f backend frontend
```

Stop:

```powershell
docker compose down
```

Stop and remove volumes:

```powershell
docker compose down -v
```
