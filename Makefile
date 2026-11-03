.PHONY: build test vet fmt ci lab clean

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w engine cmd

ci: vet build test

# Defensive proof-of-value lab. Needs node + python3; the interim engine also
# needs go + bwrap + strace. See docs/SECURITY_TESTING.md.
lab:
	cd tests/security-lab && ./run-lab.sh

clean:
	go clean ./...
	rm -rf tests/security-lab/evidence
