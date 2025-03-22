PYTHON ?= python3

.PHONY: check list

check:
	$(PYTHON) scripts/check.py

list:
	@find sysadmin security practice -name '*.py' ! -name '_*' | sort
