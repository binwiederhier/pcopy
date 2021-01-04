GO=go1.16beta1
VERSION := $(shell git describe --tag)

.PHONY:

help:
	@echo "Typical commands:"
	@echo "  make check                       - Run all tests, vetting/formatting checks and linters"
	@echo "  make fmt build-snapshot install  - Build latest and install to local system"
	@echo
	@echo "Test/check:"
	@echo "  make test                        - Run tests"
	@echo "  make coverage                    - Run tests and show coverage"
	@echo
	@echo "Lint/format:"
	@echo "  make fmt                         - Run 'go fmt'"
	@echo "  make fmt-check                   - Run 'go fmt', but don't change anything"
	@echo "  make vet                         - Run 'go vet'"
	@echo "  make lint                        - Run 'golint'"
	@echo
	@echo "Build:"
	@echo "  make build                       - Build"
	@echo "  make build-snapshot              - Build snapshot"
	@echo "  make build-simple                - Build (using go build, without goreleaser)"
	@echo "  make clean                       - Clean build folder"
	@echo
	@echo "Releasing (requires goreleaser):"
	@echo "  make release                     - Create a release"
	@echo "  make release-snapshot            - Create a test release"
	@echo
	@echo "Install locally (requires sudo):"
	@echo "  make install                     - Copy binary from dist/ to /usr/bin"
	@echo "  make install-deb                 - Install .deb from dist/"
	@echo "  make install-lint                - Install golint"


# Test/check targets

check: test fmt-check vet lint

test: .PHONY
	$(GO) test

coverage:
	$(GO) test -cover -coverprofile=profile.cov
	$(GO) tool cover -func profile.cov
	rm -f profile.cov


# Lint/formatting targets

fmt:
	$(GO) fmt ./...

fmt-check:
	@dirty="`find -name '*.go' | grep -v vendor/ | xargs gofmt -l`"; \
	if [ -n "$$dirty" ]; then \
	  echo "gofmt has warnings, run 'make fmt' to fix:\n$$dirty"; \
	  exit 1; \
	else \
	  echo "gofmt ok"; \
	fi

vet:
	$(GO) vet ./...

lint:
	which golint || $(GO) get -u golang.org/x/lint/golint
	$(GO) list ./... | grep -v /vendor/ | xargs -L1 golint -set_exit_status


# Building targets

build: .PHONY
	goreleaser build --rm-dist

build-snapshot:
	goreleaser build --snapshot --rm-dist

build-simple: clean
	mkdir -p dist/pcopy_linux_amd64
	$(GO) build \
		-o dist/pcopy_linux_amd64/pcopy \
		-ldflags \
		"-s -w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD) -X main.date=$(shell date +%s)" \
		cmd/pcopy/*.go

clean: .PHONY
	rm -rf dist


# Releasing targets

release:
	goreleaser release --rm-dist

release-snapshot:
	goreleaser release --snapshot --skip-publish --rm-dist


# Installing targets

install:
	sudo rm -f /usr/bin/pcopy
	sudo cp -a dist/pcopy_linux_amd64/pcopy /usr/bin/pcopy

install-deb:
	sudo systemctl stop pcopy || true
	sudo apt-get purge pcopy || true
	sudo dpkg -i dist/*.deb
