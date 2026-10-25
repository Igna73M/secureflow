.PHONY: ci test test-python test-api build-dashboard gate-test scan-engine

ci: test gate-test scan-engine

test: test-python test-api

test-python:
	python -m pytest -v

test-api: build-dashboard
	cd api && npm test

build-dashboard:
	cd dashboard && npm install && npm run build

gate-test:
	python scripts/verify_gate.py

scan-engine:
	python -m engine.cli scan engine
