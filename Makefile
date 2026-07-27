.PHONY: install install-browser test lint run docker clean help

help:
	@echo "install         install python deps (into active venv)"
	@echo "install-browser install the Playwright Chromium binary"
	@echo "test            run the full regression suite"
	@echo "lint            run ruff"
	@echo "run             launch the Streamlit app"
	@echo "docker          build the container image"
	@echo "clean           remove caches, backups, __pycache__"

install:
	pip install --upgrade pip && pip install -r requirements.txt

install-browser:
	python -m playwright install chromium

test:
	FACEHUNTER_SKIP_INSTALL=1 python -m pytest tests/ -q

lint:
	ruff check FaceFinderPRO.py tests/

run:
	streamlit run FaceFinderPRO.py

docker:
	docker build -t facehunter-pro:latest .

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + ; \
	rm -f *.pkl *.pkl.bak* *.pkl.corrupt *.archive.pkl
