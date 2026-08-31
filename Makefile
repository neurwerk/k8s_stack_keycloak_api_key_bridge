.PHONY: check check-lock check-ruff check-ty check-test check-package test build

check: check-lock check-ruff check-ty check-test check-package

check-lock:
	uv lock --check

check-ruff:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .

check-ty:
	uv run --frozen ty check

check-test:
	uv run --frozen pytest -v

check-package:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	uv build --out-dir "$$tmp"

test: check-test

build:
	docker build -t keycloak-api-key-bridge:local .
