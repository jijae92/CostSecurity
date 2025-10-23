.PHONY: up test dry-run build deploy delete

VENV ?= .venv
PYTHON ?= python3
PIP ?= $(VENV)/bin/pip
PYTHON_BIN ?= $(VENV)/bin/python

up:
	@if [ ! -d "$(VENV)" ]; then $(PYTHON) -m venv $(VENV); fi
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test:
	$(VENV)/bin/pytest -q

dry-run: up
	mkdir -p artifacts
	DRY_RUN=true $(PYTHON_BIN) -m src.correlate.handler --dry-run --use-sample-data --out artifacts/weekly_report.json
	DRY_RUN=true $(PYTHON_BIN) -m src.reporter.handler --dry-run --in artifacts/weekly_report.json

build:
	sam build

deploy:
	sam deploy --guided

delete:
	sam delete
