UV := uv

.PHONY: install test lint format typecheck licence-check targets-up targets-down targets-status corpus scan check

install:
	$(UV) sync

test:
	$(UV) run pytest

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck:
	$(UV) run mypy

licence-check:
	$(UV) run python -m cli.licences

targets-up:
	docker compose up -d
	@echo "waiting for targets to answer..."
	@sleep 5
	@$(MAKE) --no-print-directory targets-status

targets-down:
	docker compose down

targets-status:
	@docker compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'

corpus:
	$(UV) run python -m cli.corpus

scan:
	$(UV) run python -m cli.main $(ARGS)

check: lint typecheck test licence-check
