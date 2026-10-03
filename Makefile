.PHONY: dev lint selftest test check demo gate clean

dev:
	python -m pip install -e ".[dev]"

lint:
	ruff check .

selftest:
	cryptomigrate selftest

test:
	pytest

check: lint selftest test

demo:
	bash examples/demo/run_demo.sh demo-workspace

gate:
	cryptomigrate discover . --no-data --no-tls --out artifacts/self-scan --fail-on high

clean:
	rm -rf demo-workspace artifacts .pytest_cache .ruff_cache build dist src/*.egg-info
