.PHONY:

help:
	@echo "Build:"
	@echo "  make all   - Build all deliverables"
	@echo "  make cmd   - Build the pcopy CLI tool"
	@echo "  make clean - Clean build folder"

all: clean cmd

clean: .PHONY
	@echo == Cleaning ==
	rm -rf build
	@echo

cmd: .PHONY
	@echo == Building pcopy CLI ==
	mkdir -p build/cmd
	go build -o build/cmd/pcopy cmd/pcopy/main.go
	@echo
	@echo "--> pcopy CLI built at build/cmd/pcopy"
	@echo
