# =============================================================================
# SVT System — Makefile
# =============================================================================

.PHONY: help dev down logs db-shell redis-shell test lint backend frontend clean

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------
dev: ## Start all dev infrastructure (Postgres, Redis, Prometheus, Grafana, Loki)
	docker-compose -f infra/docker-compose.yml up -d
	@echo "✅ Infrastructure started. Waiting for health checks..."
	@sleep 10
	@docker-compose -f infra/docker-compose.yml ps

down: ## Stop all dev infrastructure
	docker-compose -f infra/docker-compose.yml down

down-volumes: ## Stop all dev infrastructure and remove volumes
	docker-compose -f infra/docker-compose.yml down -v

logs: ## Tail infra logs
	docker-compose -f infra/docker-compose.yml logs -f --tail=100

db-shell: ## Open psql shell
	docker exec -it svt-postgres psql -U svt_admin -d svt

redis-shell: ## Open redis-cli shell
	docker exec -it svt-redis redis-cli -a $${REDIS_PASSWORD:-svt_dev_redis_password}

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------
backend-install: ## Install backend dependencies
	cd backend && pip install -r requirements.txt

backend-dev: ## Run backend dev server
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

backend-migrate: ## Run Alembic migrations
	cd backend && alembic upgrade head

backend-migrate-down: ## Rollback one migration
	cd backend && alembic downgrade -1

backend-migrate-create: ## Create new migration (usage: make backend-migrate-create MSG="description")
	cd backend && alembic revision --autogenerate -m "$(MSG)"

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-dev: ## Run frontend dev server
	cd frontend && npm run dev

frontend-build: ## Build frontend for production
	cd frontend && npm run build

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
test: ## Run all backend tests
	cd backend && python -m pytest tests/ -v --cov=app --cov-report=term-missing

test-unit: ## Run unit tests only
	cd backend && python -m pytest tests/unit/ -v

test-integration: ## Run integration tests (requires running infra)
	cd backend && python -m pytest tests/integration/ -v

test-e2e: ## Run Playwright e2e tests
	cd frontend && npx playwright test

# ---------------------------------------------------------------------------
# Linting & Type Checking
# ---------------------------------------------------------------------------
lint: ## Run all linters
	cd backend && ruff check app/ tests/
	cd frontend && npx eslint src/

typecheck: ## Run type checkers
	cd backend && mypy app/
	cd frontend && npx tsc --noEmit

format: ## Auto-format code
	cd backend && ruff format app/ tests/
	cd frontend && npx prettier --write src/

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
docker-build: ## Build all Docker images
	docker build -t svt-backend:latest backend/
	docker build -t svt-frontend:latest frontend/

docker-scan: ## Security scan Docker images
	trivy image svt-backend:latest --severity CRITICAL
	trivy image svt-frontend:latest --severity CRITICAL

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
clean: ## Remove generated files, caches, and __pycache__
	find backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find backend -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find backend -name "*.pyc" -delete 2>/dev/null || true
	rm -rf frontend/dist frontend/node_modules/.cache 2>/dev/null || true
