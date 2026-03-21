UV := /Users/vinayakkannan/.local/bin/uv

.PHONY: install test test-unit test-scenario test-integration lint fmt typecheck up down migrate seed benchmark

install:
	$(UV) sync

test:
	$(UV) run python -m pytest -v

test-unit:
	$(UV) run python -m pytest -m unit -v

test-scenario:
	$(UV) run python -m pytest -m scenario -v

test-integration:
	$(UV) run python -m pytest -m integration -v

lint:
	$(UV) run ruff check gateway/ tests/

fmt:
	$(UV) run ruff format gateway/ tests/

typecheck:
	$(UV) run mypy gateway/ --strict

up:
	docker compose up -d

down:
	docker compose down

migrate:
	$(UV) run alembic upgrade head

seed:
	$(UV) run python scripts/seed_policies.py

benchmark:
	$(UV) run python scripts/run_benchmark.py
