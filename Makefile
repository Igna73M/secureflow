
.PHONY: test test-python test-api

test: test-python test-api

test-python:
	python -m pytest -v

test-api:
	cd api && npm test
