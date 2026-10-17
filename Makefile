.PHONY: ci test test-python test-api gate-test scan-engine

ci: test gate-test scan-engine

test: test-python test-api

test-python:
	python -m pytest -v

test-api:
	cd api && npm test

gate-test:
	python scripts/verify_gate.py

scan-engine:
	python -m engine.cli scan engine
