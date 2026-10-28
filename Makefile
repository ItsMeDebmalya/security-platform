UV := uv

.PHONY: web-lab-up web-lab-down install test lint format typecheck licence-check cve-check rfc-check targets-up targets-down targets-status crosscheck corpus scan check

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

rfc-check:
	$(UV) run python -m cli.rfcs

licence-check:
	$(UV) run python -m cli.licences

cve-check:
	$(UV) run python -m cli.cves

targets-up:
	docker compose up -d
	@echo "waiting for targets to answer..."
	@sleep 5
	@$(MAKE) --no-print-directory targets-status

targets-down:
	docker compose down

targets-status:
	@docker compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'

crosscheck:
	@test -x tools/bin/testssl.sh-3.2.4/testssl.sh || tools/fetch-testssl.sh
	$(UV) run python -m corpus.crosscheck.testssl

corpus:
	$(UV) run python -m cli.corpus

scan:
	$(UV) run python -m cli.main $(ARGS)

check: lint typecheck test licence-check cve-check

web-lab-up:
	$(UV) run python -m corpus.generators.web certs
	docker compose --profile web-lab up -d web-lab-nginx web-lab-django web-lab-pytrace
	@sleep 8

web-lab-down:
	docker compose --profile web-lab rm -sf web-lab-nginx web-lab-django web-lab-pytrace
