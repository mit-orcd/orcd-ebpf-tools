SHELL := /bin/bash
.DEFAULT_GOAL := help

REPO_ROOT := $(abspath $(CURDIR)/..)
BUILD_DIR := $(CURDIR)/_build
RPM_TOPDIR := $(BUILD_DIR)/rpmbuild
SOURCES_DIR := $(RPM_TOPDIR)/SOURCES
SPECS_DIR := $(RPM_TOPDIR)/SPECS
RESULT_DIR := $(BUILD_DIR)/result

COMMIT ?= $(shell git -C "$(REPO_ROOT)" rev-parse HEAD)
SHORT_COMMIT := $(shell printf '%s' "$(COMMIT)" | cut -c1-7)
SOURCE_DATE_EPOCH ?= $(shell git -C "$(REPO_ROOT)" show -s --format=%ct "$(COMMIT)")
SOURCE_ARCHIVE := $(SOURCES_DIR)/orcd-ebpf-tools-$(COMMIT).tar.gz
VENDOR_ARCHIVE := $(SOURCES_DIR)/bmask-vendor-$(COMMIT).tar.gz
VMLINUX_HEADER := $(SOURCES_DIR)/vmlinux.h

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
MOCK_CONFIG ?= rocky-9-x86_64
SPEC := $(CURDIR)/packaging/bmask.spec

.PHONY: help check-tools build test source vendor vmlinux sources srpm rpm mock clean

help: ## Show the available targets.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check-tools: ## Check tools needed to prepare and build the RPM.
	@missing=0; \
	for tool in git go tar gzip bpftool clang rpmbuild; do \
		command -v "$$tool" >/dev/null || { echo "missing: $$tool" >&2; missing=1; }; \
	done; \
	if [ $$missing -eq 0 ]; then \
		echo "have all tools to build"; \
	fi; \
	exit $$missing

build: bpf/vmlinux.h ## Build bmask locally (generates and embeds the BPF object).
	GOFLAGS=-mod=mod CGO_ENABLED=0 go generate ./...
	GOFLAGS=-mod=mod CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bmask .

test: bpf/vmlinux.h ## Generate the BPF bindings and run Go tests locally.
	GOFLAGS=-mod=mod CGO_ENABLED=0 go generate ./...
	GOFLAGS=-mod=mod CGO_ENABLED=0 go test ./...

bpf/vmlinux.h:
	@test -r "$(VMLINUX_BTF)" || { \
		echo "Cannot read kernel BTF: $(VMLINUX_BTF)" >&2; \
		echo "Set VMLINUX_BTF=/path/to/a/vmlinux BTF file." >&2; \
		exit 1; \
	}
	bpftool btf dump file "$(VMLINUX_BTF)" format c > "$@.tmp"
	mv "$@.tmp" "$@"

$(SOURCES_DIR) $(SPECS_DIR) $(RESULT_DIR):
	mkdir -p "$@"

source: $(SOURCE_ARCHIVE) ## Create a deterministic archive of the pinned Git commit.

$(SOURCE_ARCHIVE): | $(SOURCES_DIR)
	@echo "Creating $@ from $(COMMIT)"
	@git -C "$(REPO_ROOT)" cat-file -e "$(COMMIT)^{commit}"
	@git -C "$(REPO_ROOT)" archive \
		--format=tar \
		--prefix="orcd-ebpf-tools-$(COMMIT)/" \
		"$(COMMIT)" | gzip -n > "$@.tmp"
	@mv "$@.tmp" "$@"

vendor: $(VENDOR_ARCHIVE) ## Download Go modules and create the offline vendor archive.

$(VENDOR_ARCHIVE): | $(SOURCES_DIR)
	@echo "Vendoring Go modules for $(COMMIT)"
	@tmp="$$(mktemp -d)"; \
	trap 'rm -rf -- "$$tmp"' EXIT; \
	git -C "$(REPO_ROOT)" archive "$(COMMIT)" bmask/go.mod bmask/go.sum | tar -x -C "$$tmp"; \
	(cd "$$tmp/bmask" && GOTOOLCHAIN=auto go mod vendor); \
	tar --sort=name --owner=0 --group=0 --numeric-owner \
		--mtime="@$(SOURCE_DATE_EPOCH)" -C "$$tmp/bmask" -cf - vendor | \
		gzip -n > "$@.tmp"; \
	mv "$@.tmp" "$@"

vmlinux: $(VMLINUX_HEADER) ## Generate the versioned build input vmlinux.h.

$(VMLINUX_HEADER): | $(SOURCES_DIR)
	@test -r "$(VMLINUX_BTF)" || { \
		echo "Cannot read kernel BTF: $(VMLINUX_BTF)" >&2; \
		echo "Set VMLINUX_BTF=/path/to/a/vmlinux BTF file." >&2; \
		exit 1; \
	}
	bpftool btf dump file "$(VMLINUX_BTF)" format c > "$@.tmp"
	mv "$@.tmp" "$@"

sources: source vendor vmlinux | $(SPECS_DIR) ## Prepare every file rpmbuild needs.
	cp -f "$(SPEC)" "$(SPECS_DIR)/bmask.spec"
	cp -f "$(CURDIR)/packaging/bmask.service" "$(SOURCES_DIR)/bmask.service"
	cp -f "$(CURDIR)/packaging/bmask.sysconfig" "$(SOURCES_DIR)/bmask.sysconfig"
	cd "$(SOURCES_DIR)" && sha256sum \
		"$$(basename "$(SOURCE_ARCHIVE)")" \
		"$$(basename "$(VENDOR_ARCHIVE)")" \
		"$$(basename "$(VMLINUX_HEADER)")" \
		bmask.service bmask.sysconfig > SHA256SUMS

srpm: sources ## Build the source RPM with rpmbuild.
	rpmbuild -bs "$(SPECS_DIR)/bmask.spec" \
		--define "_topdir $(RPM_TOPDIR)" \
		--define "commit $(COMMIT)" \
		--define "shortcommit $(SHORT_COMMIT)"

rpm: sources ## Build source and binary RPMs with rpmbuild.
	rpmbuild -ba "$(SPECS_DIR)/bmask.spec" \
		--define "_topdir $(RPM_TOPDIR)" \
		--define "commit $(COMMIT)" \
		--define "shortcommit $(SHORT_COMMIT)"

mock: sources | $(RESULT_DIR) ## Build the RPM in Mock (MOCK_CONFIG=rocky-9-x86_64).
	mock -r "$(MOCK_CONFIG)" --buildsrpm \
		--spec "$(SPECS_DIR)/bmask.spec" \
		--define "commit $(COMMIT)" \
		--define "shortcommit $(SHORT_COMMIT)" \
		--sources "$(SOURCES_DIR)" \
		--resultdir "$(RESULT_DIR)/srpm"
	@srpm="$$(find "$(RESULT_DIR)/srpm" -maxdepth 1 -name 'bmask-*.src.rpm' -print -quit)"; \
	test -n "$$srpm" || { echo "Mock did not produce a source RPM" >&2; exit 1; }; \
	mkdir -p "$(RESULT_DIR)/rpm"; \
	mock -r "$(MOCK_CONFIG)" --rebuild "$$srpm" \
		--define "commit $(COMMIT)" \
		--define "shortcommit $(SHORT_COMMIT)" \
		--resultdir "$(RESULT_DIR)/rpm"

clean: ## Remove generated local build and packaging artifacts.
	rm -rf -- "$(CURDIR)/_build"
	rm -f -- bmask chmodblock_bpfeb.go chmodblock_bpfel.go
