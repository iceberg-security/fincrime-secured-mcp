PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

.PHONY: help install lint test typecheck clean register-plugin load-fixtures validate-evals evals evals-smoke gen-keys compose-up compose-down compose-logs compose-ps

help:
	@echo "Targets:"
	@echo "  install          - create virtualenv and install dev + runtime deps"
	@echo "  lint             - run ruff check"
	@echo "  typecheck        - run mypy"
	@echo "  test             - run pytest"
	@echo "  clean            - remove virtualenv and caches"
	@echo "  register-plugin  - validate + install the plugin into Cowork"
	@echo "  gen-keys         - generate Ed25519 keypairs under config/keys/"
	@echo "  compose-up       - generate keys (if missing) and bring up the M0 stack"
	@echo "  compose-down     - tear down the stack (preserves audit volume)"
	@echo "  compose-logs     - tail logs for all services"
	@echo "  compose-ps       - list compose service status"
	@echo "  load-fixtures    - seed scenario personas across mock APIs (placeholder)"
	@echo "  validate-evals   - lint all eval dataset YAMLs"
	@echo "  evals            - run full eval suite (US-030)"
	@echo "  evals-smoke      - run smoke subset of evals (US-030)"

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: $(VENV)/bin/activate
	$(PIP) install -e ".[dev]"

lint: $(VENV)/bin/activate
	$(VENV)/bin/ruff check .

typecheck: $(VENV)/bin/activate
	$(VENV)/bin/mypy gateways mcp_servers mock_apis evals

test: $(VENV)/bin/activate
	$(VENV)/bin/pytest

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

register-plugin: $(VENV)/bin/activate
	$(PY) -m plugin.register

gen-keys: $(VENV)/bin/activate
	$(PY) scripts/gen_dev_keys.py

compose-up: gen-keys
	docker compose up -d --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f

compose-ps:
	docker compose ps

load-fixtures: $(VENV)/bin/activate
	$(PY) scripts/load_fixtures.py

validate-evals: $(VENV)/bin/activate
	$(PY) -m evals.validate

evals: $(VENV)/bin/activate
	$(PY) -m evals.run

evals-smoke: $(VENV)/bin/activate
	$(PY) -m evals.run --smoke
