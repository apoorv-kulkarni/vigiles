BINARY := vigiles
GOFLAGS := -ldflags "-s -w"

.PHONY: build test test-live vet clean install run

build:
	go build $(GOFLAGS) -o $(BINARY) .

test:
	go test ./... -v -count=1

# Contract tests against the live OSV API. Kept out of `test` so CI stays
# offline-safe; run these when changing the OSV integration.
test-live:
	go test ./internal/checker/ -tags osvlive -run 'TestLive' -v -count=1

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

install: build
	cp $(BINARY) $(GOPATH)/bin/ 2>/dev/null || cp $(BINARY) ~/go/bin/

run: build
	./$(BINARY) scan --verbose

release:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o dist/$(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o dist/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-windows-amd64.exe .
