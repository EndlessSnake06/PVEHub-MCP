SHELL := /bin/bash
PY := .venv/bin/python
UV := uv

.PHONY: help install lock fmt lint typecheck test check run run-stdio docker-build docker-up docs-tools clean

help:
	@echo "install      create .venv and install dev dependencies"
	@echo "lock         refresh uv.lock"
	@echo "fmt          ruff format + import sort"
	@echo "lint         ruff check"
	@echo "typecheck    mypy src"
	@echo "test         pytest (unit/contract tests)"
	@echo "check        lint + typecheck + test"
	@echo "run          run Streamable HTTP on 127.0.0.1:8080"
	@echo "run-stdio    run stdio transport"
	@echo "docker-build build the container image"
	@echo "docker-up    docker compose up -d --build"
	@echo "docs-tools   regenerate docs/TOOLS.md from @hub.tool declarations (static scan)"

install:
	$(UV) sync --extra dev

lock:
	$(UV) lock

fmt:
	$(UV) run ruff format src tests
	$(UV) run ruff check --fix src tests

lint:
	$(UV) run ruff check src tests

typecheck:
	$(UV) run mypy src

test:
	$(UV) run pytest

check: lint typecheck test

run:
	PVEHUB_TRANSPORT=http PVEHUB_HOST=127.0.0.1 $(UV) run pvehub-mcp

run-stdio:
	PVEHUB_TRANSPORT=stdio $(UV) run pvehub-mcp

docker-build:
	docker build -t pvehub-mcp:0.1.3 .

docker-up:
	docker compose up -d --build

docs-tools:
	$(UV) run python scripts/generate_tool_docs.py > docs/TOOLS.md

clean:
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache dist build
