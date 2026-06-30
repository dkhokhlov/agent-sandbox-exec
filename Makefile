# agent-sandbox-exec — convenience workflow targets.
# CMake is the build engine; this Makefile just orchestrates the common commands.

CMAKE    ?= cmake
BUILD    ?= build
BUILDTYPE ?= Release

# Build toolchain (build deps). Runtime deps ship in the .deb's Depends.
DEPS := clang llvm libelf-dev libbpf-dev bpftool

.PHONY: deps build package test ci clean install

## deps     install build toolchain (sudo apt install)
deps:
	sudo apt-get update && sudo apt-get install -y $(DEPS)

## build    configure + compile (unprivileged)
build:
	$(CMAKE) -B $(BUILD) -DCMAKE_BUILD_TYPE=$(BUILDTYPE)
	$(CMAKE) --build $(BUILD) --parallel

## package  build the .deb via CPack
package: build
	(cd $(BUILD) && cpack -G DEB)

## test     unit (BPF object loads) + integration (deny / env-unchanged) when daemon is up
test: build
	scripts/test.sh

## ci       clean, reproducible CI run (no sudo): build + test + package
ci: clean build test package

## clean    remove build artifacts
clean:
	rm -rf $(BUILD)

## install  install the built .deb (sudo)
install: package
	sudo apt-get install -y $(BUILD)/agent-sandbox-exec_*.deb
