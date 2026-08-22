UV := uv

.PHONY: install test lint format typecheck licence-check corpus scan check

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

corpus:
	$(UV) run python -m cli.corpus

scan:
	$(UV) run python -m cli.main $(ARGS)

check: lint typecheck test licence-check
