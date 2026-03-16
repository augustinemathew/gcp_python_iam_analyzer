.PHONY: install dev lint fmt test test-cov clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/ build_pipeline/

fmt:
	ruff format src/ tests/ build_pipeline/
	ruff check --fix src/ tests/ build_pipeline/

test:
	pytest

test-cov:
	pytest --cov=gcp_sdk_detector --cov-report=term-missing

clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache .coverage htmlcov dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
