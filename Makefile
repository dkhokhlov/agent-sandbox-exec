# agent-sandbox-exec — convenience workflow targets.
# CMake is the build engine; this Makefile just orchestrates the common commands.

CMAKE    ?= cmake
BUILD    ?= build
BUILDTYPE ?= Release

# Build toolchain (build deps). Runtime deps ship in the .deb's Depends.
DEPS := clang llvm libelf-dev libbpf-dev bpftool

.PHONY: help deps build package test ci clean install

.DEFAULT_GOAL := help

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Install build toolchain (sudo apt install)
	sudo apt-get update && sudo apt-get install -y $(DEPS)

build: ## Configure + compile (unprivileged): cmake + clang -target bpf + skeleton + daemon
	$(CMAKE) -B $(BUILD) -DCMAKE_BUILD_TYPE=$(BUILDTYPE)
	$(CMAKE) --build $(BUILD) --parallel

package: build ## Build the .deb via CPack
	(cd $(BUILD) && cpack -G DEB)

test: build ## Phase A (no root): BPF object has expected program + maps; Phase B when daemon is up
	scripts/test.sh

ci: clean build test package ## Clean, reproducible CI run (no sudo)
clean: ## Remove build artifacts
	rm -rf $(BUILD)

install: package ## Install the built .deb (sudo)
	sudo apt-get install -y ./$(BUILD)/agent-sandbox-exec_*.deb
