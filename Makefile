PYTHON ?= python3
.PHONY: run test format-check
run:
	$(PYTHON) -m sentinel.demo
test:
	$(PYTHON) -m unittest discover -s tests -v
format-check:
	$(PYTHON) -m black --check sentinel tests
