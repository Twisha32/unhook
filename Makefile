.PHONY: help setup test lint samples notes-check eval-demo demo-data dashboard dev-api up down

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

help:
	@echo "make setup        create a virtualenv and install the backend and sandbox"
	@echo "make test         run the backend and sandbox test suites"
	@echo "make lint         ruff over both Python packages"
	@echo "make samples      check the sample messages against their expected verdicts"
	@echo "make notes-check  confirm the case-note checker catches seeded fabrications"
	@echo "make eval-demo    evaluate on the synthetic corpus (plumbing check, not a benchmark)"
	@echo "make demo-data    rebuild the JSON the dashboard demo runs on"
	@echo "make dashboard    install and build the dashboard"
	@echo "make dev-api      API on :8000 with inline tasks (no Redis, no Postgres)"
	@echo "make up / down    the full Docker stack"

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q -e "backend[dev]" -e "sandbox[browser,dev]"

test:
	$(BIN)/pytest backend sandbox

lint:
	$(BIN)/ruff check backend sandbox

samples:
	$(BIN)/unhook samples

notes-check:
	$(BIN)/unhook notes-check

eval-demo:
	$(BIN)/unhook eval --out eval/reports/latest.json --write-model model/model.json

demo-data:
	$(BIN)/unhook demo-data --out dashboard/public/demo

dashboard:
	cd dashboard && npm ci && npm run build

dev-api:
	UNHOOK_EAGER=true $(BIN)/uvicorn unhook.main:app --reload --port 8000

up:
	docker compose up --build

down:
	docker compose down
