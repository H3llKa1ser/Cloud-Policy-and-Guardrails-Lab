# Cloud Policy & Guardrails Lab
#
#   make            run everything CI runs
#   make gate-compliant / gate-noncompliant
#   make verify     assert the noncompliant stack trips exactly the expected rules

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := all

MODULES := $(wildcard modules/*)
STACKS  := examples/compliant examples/noncompliant

.PHONY: all fmt fmt-check lint validate test-policies test-modules plans controls controls-check \
        gate-compliant gate-noncompliant verify scan clean lock

all: fmt-check lint validate test-policies controls-check test-modules gate-compliant verify

fmt:
	terraform fmt -recursive
	opa fmt --write policies

fmt-check:
	terraform fmt -check -recursive
	opa fmt --list --fail policies

lint:
	tflint --init
	tflint --recursive --config "$(CURDIR)/.tflint.hcl"

validate:
	@for d in $(MODULES) $(STACKS); do \
	  echo "validate $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null; \
	  terraform -chdir=$$d validate -no-color; \
	done

test-policies:
	opa check --strict policies
	opa test policies --coverage --threshold 95 >/dev/null
	opa test policies

test-modules:
	@for d in $(MODULES); do \
	  echo "terraform test $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null; \
	  terraform -chdir=$$d test -no-color; \
	done

plans: $(addsuffix /plan.json,$(STACKS))

examples/%/plan.json: examples/%/*.tf $(shell find modules -name '*.tf')
	scripts/plan.sh examples/$*

gate-compliant: examples/compliant/plan.json
	scripts/gate.sh examples/compliant

# Expected to fail: shows what the guardrails catch.
gate-noncompliant: examples/noncompliant/plan.json
	-scripts/gate.sh examples/noncompliant

verify: examples/noncompliant/plan.json
	scripts/assert-violations.sh examples/noncompliant

# Compliance mapping (policy METADATA -> CIS / NIST / AWS FSBP).
controls:
	python3 scripts/controls.py catalogue > docs/CONTROLS.md

controls-check:
	python3 scripts/controls.py check
	@python3 scripts/controls.py catalogue | diff -u docs/CONTROLS.md - \
	  || { echo "docs/CONTROLS.md is stale: run 'make controls'" >&2; exit 1; }

# Compliance view of one stack's plan, e.g. `make report-noncompliant`.
report-%: examples/%/plan.json
	@scripts/gate.sh examples/$* --output json --no-color > examples/$*/results.json || true
	@python3 scripts/controls.py report examples/$*/results.json --plan examples/$*

scan:
	checkov --config-file .checkov.yaml

clean:
	find . -name '.terraform' -type d -prune -exec rm -rf {} +
	find . \( -name 'tfplan' -o -name 'plan.json' -o -name 'results.json' -o -name 'compliance.json' \) -delete
	find modules -name '.terraform.lock.hcl' -delete

lock:
	@for d in examples/*; do \
	  terraform -chdir=$$d providers lock \
	    -platform=linux_amd64 -platform=linux_arm64 \
	    -platform=darwin_amd64 -platform=darwin_arm64 -platform=windows_amd64; \
	done
