# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test Commands
- Build: `go build -v`
- Lint: `goimports -w -l .`
- Test all: `go test -v`
- Test single: `go test -v -run TestName`
- Install deps: `go get -v -t .`

## Code Style Guidelines
- Imports: Standard library first, then third-party imports with blank line separator
- Formatting: Follow standard Go format with goimports
- Error handling: Return detailed errors with context, use fmt.Errorf with %w for wrapping
- Logging: Use slog with appropriate levels (Debug, Info, Warn, Error)
- Concurrency: Use sync.Mutex for locking where needed
- Naming: Follow Go conventions (e.g., exported names PascalCase)
- Comments: Document exported functions with complete sentences
- Testing: Use simulator for TPM tests, verify functionality with test cases