# dpt — build matrix: dist/dpt-<os>-<arch>[.exe] and dist/SHA256SUMS
VER ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TARGETS = darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

.PHONY: all dist test clean
all: dist

dist:
	@mkdir -p dist
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w -X main.version=$(VER)" \
			-o dist/dpt-$$os-$$arch$$ext ./cmd/dpt; \
	done
	@cd dist && sha256sum dpt-* > SHA256SUMS && cat SHA256SUMS

test:
	go vet ./...
	go test ./...

clean:
	rm -rf dist
