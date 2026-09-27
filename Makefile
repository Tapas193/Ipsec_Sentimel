# -----------------------------------------------------------------------------
# IPsec Sentinel — developer Makefile (Phase 1)
# -----------------------------------------------------------------------------

SHELL := /bin/bash

PYTHON     ?= python3
BACKEND    := backend
FRONTEND   := frontend
VENV       := .venv
PIP        := $(VENV)/bin/pip
UVICORN    := $(VENV)/bin/uvicorn
PYTEST     := $(VENV)/bin/pytest
RUFF       := $(VENV)/bin/ruff
MYPY       := $(VENV)/bin/mypy
ALEMBIC    := $(VENV)/bin/alembic

.PHONY: help install install-backend install-frontend \
        dev dev-backend dev-frontend \
        test lint typecheck build \
        migrate downgrade \
        db-shell psql \
        docker-up docker-down docker-build docker-build-multi docker-logs \
        testbed-up testbed-shell testbed-down \
        clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# -- Installation -----------------------------------------------------------

install: install-backend install-frontend ## Install backend + frontend dependencies

install-backend: ## Install backend Python dependencies (in .venv)
	python3 -m venv $(VENV)
	$(PIP) install -e "$(BACKEND)[dev]"

install-frontend: ## Install frontend npm dependencies
	npm --prefix $(FRONTEND) install

# -- Local development (no Docker) -----------------------------------------

dev: ## Bring up backend + frontend (background); see dev-backend / dev-frontend logs
	$(MAKE) -j2 dev-backend dev-frontend

dev-backend: ## Run the FastAPI backend against DATABASE_URL
	cd $(BACKEND) && $(ALEMBIC) upgrade head
	cd $(BACKEND) && $(UVICORN) app.main:app --host 0.0.0.0 --port 8000 --reload

dev-frontend: ## Run the Vite dev server (http://localhost:2456)
	npm --prefix $(FRONTEND) run dev

# -- Quality gates ----------------------------------------------------------

test: ## Run backend test suite
	cd $(BACKEND) && $(PYTEST)

lint: ## Lint backend (ruff) and frontend (eslint)
	cd $(BACKEND) && $(RUFF) check app tests
	cd $(BACKEND) && $(RUFF) format --check app tests
	npm --prefix $(FRONTEND) run lint

typecheck: ## Type-check backend (mypy) and frontend (tsc)
	cd $(BACKEND) && $(MYPY) app tests
	npm --prefix $(FRONTEND) run typecheck

build: ## Build frontend for production
	npm --prefix $(FRONTEND) run build

# -- Database ---------------------------------------------------------------

migrate: ## Apply Alembic migrations to DATABASE_URL
	cd $(BACKEND) && $(ALEMBIC) upgrade head

downgrade: ## Revert the latest Alembic migration
	cd $(BACKEND) && $(ALEMBIC) downgrade -1

db-shell: ## Open a psql shell against DATABASE_URL
	psql "$$DATABASE_URL"

# -- Docker -----------------------------------------------------------------

# Container platform. Defaults to the host architecture (linux/arm64 on
# Apple Silicon M-series); override with DOCKER_PLATFORM=linux/amd64 etc.
DOCKER_PLATFORM ?= $(shell uname -m | grep -qE 'arm64|aarch64' && echo linux/arm64 || echo linux/amd64)

docker-up: ## Build and start all services (frontend at :8080, backend at :8000)
	DOCKER_PLATFORM=$(DOCKER_PLATFORM) docker compose up -d --build

docker-down: ## Stop all services
	docker compose down

docker-build: ## Rebuild images for the host platform
	DOCKER_PLATFORM=$(DOCKER_PLATFORM) docker compose build

# Multi-arch image build with BuildKit/buildx (produces amd64 + arm64).
docker-build-multi: ## Cross-build backend+frontend images for amd64 and arm64
	@test -n "$$(docker buildx ls >/dev/null 2>&1 && echo yes)" || \
	  (echo "Docker BuildKit buildx not available: run 'docker buildx create --use'" && exit 1)
	docker buildx build --platform linux/amd64,linux/arm64 -t ipsec-sentinel-backend ./backend
	docker buildx build --platform linux/amd64,linux/arm64 -t ipsec-sentinel-frontend ./frontend

docker-logs: ## Tail logs for all services
	docker compose logs -f

# ARM64 testbed (lima) — lightweight Linux ARM64 VM for the future
# IPsec/StrongSwan testbed. macOS cannot run StrongSwan natively; it runs
# inside this Linux/arm64 VM. See scripts/arm64-testbed.sh.
testbed-up: ## Create + start the lima Linux/arm64 testbed VM
	./scripts/arm64-testbed.sh up

testbed-shell: ## Open a shell inside the testbed VM
	./scripts/arm64-testbed.sh shell

testbed-down: ## Stop the testbed VM
	./scripts/arm64-testbed.sh stop

# -- Cleanup ----------------------------------------------------------------

clean: ## Remove build artifacts and caches
	rm -rf $(FRONTEND)/dist frontend/node_modules .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +