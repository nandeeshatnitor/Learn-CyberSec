SHELL := /bin/bash
VENV  := backend/.venv
PY    := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help setup install up down logs migrate seed backend-dev frontend-dev \
        test test-backend test-frontend lint typecheck smoke verify-providers fake-providers

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Create .env with generated random passwords
	./scripts/setup-env.sh

install: ## Install backend (venv) and frontend dependencies for host-based development
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -e "backend[dev]"
	cd frontend && npm ci

# --- Docker Compose --------------------------------------------------------------------------
up: ## Build and start the full stack (db, redis, migrations, backend, frontend)
	docker compose up --build -d

down: ## Stop the stack (add -v via `docker compose down -v` to also delete data)
	docker compose down

logs: ## Follow logs
	docker compose logs -f

# --- Host-based development (needs Postgres and Redis reachable per .env) --------------------
migrate: ## Apply database migrations
	cd backend && ../$(VENV)/bin/alembic upgrade head

seed: ## Load development sample CVEs (flagged as unverified seed data)
	cd backend && ../$(PY) -m app.database.seed

backend-dev: ## Run the API with auto-reload on :8000
	cd backend && ../$(VENV)/bin/uvicorn app.main:app --reload --port 8000

frontend-dev: ## Run the web app on :3000
	cd frontend && npm run dev

# --- Quality ---------------------------------------------------------------------------------
test: test-backend test-frontend ## Run all unit and API tests

test-backend:
	cd backend && ../$(PY) -m pytest

test-frontend:
	cd frontend && npm test

lint: ## Lint and format-check both projects
	cd backend && ../$(VENV)/bin/ruff check . && ../$(VENV)/bin/ruff format --check .
	cd frontend && npm run lint

typecheck: ## Static type checks
	cd backend && ../$(VENV)/bin/mypy
	cd frontend && npm run typecheck

verify-providers: ## Check the adapters against the REAL NVD/MITRE/KEV APIs (needs internet). ARGS="CVE-... --record DIR"
	$(PY) scripts/verify_providers.py $(ARGS)

fake-providers: ## Serve fake NVD/MITRE/KEV APIs on localhost:9101-9103 (dev only, see scripts/fake_providers.py)
	python3 scripts/fake_providers.py

smoke: ## End-to-end check against a running stack (BACKEND_URL / FRONTEND_URL)
	python3 tests/smoke_test.py
