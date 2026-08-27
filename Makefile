# UniNet developer tasks.  Windows: use `make` from Git Bash, or run the python
# commands directly (shown in each recipe).

.PHONY: install install-dev demo serve up live scale train eval test lint clean

install:            ## Install core runtime + editable package
	python -m pip install -e .

install-dev:        ## Install with dev + data extras
	python -m pip install -e ".[dev,data]"

demo:              ## Run the end-to-end synthetic pipeline, print JSON alerts
	python -m uninet.demo

serve up:          ## Single command: train-if-needed -> pipeline -> dashboard (login admin/uninet)
	uninet

live:              ## Dashboard that keeps refreshing detections (Phase 5 live console)
	uninet --live

scale:             ## Phase 5: parallel pipeline across 4 process workers
	uninet --workers 4

train:             ## Train the anomaly model (+ RGAT if torch is installed)
	python -m uninet.training.train_anomaly
	python -m uninet.training.train_rgat

eval:              ## Detection metrics + throughput benchmark on synthetic data
	python -m uninet.eval.metrics
	python -m uninet.eval.throughput_bench

test:              ## Run the test suite
	python -m pytest

lint:
	python -m ruff check src tests

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
