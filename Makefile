.PHONY: build test vet fmt ci lab bpf bpf-test context proof proof-real bench release install e2e clean

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
PLATFORMS ?= linux/amd64 linux/arm64 darwin/arm64

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w engine cmd cloud

ci: vet build test

# Build the Tier 1 eBPF-LSM object (needs clang).
bpf:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include \
		-c engine/enforce/live/bpf/live.bpf.c -o engine/enforce/live/bpf/live.bpf.o

# Privileged end-to-end test of the live tier (needs root).
bpf-test: bpf
	go test -tags integration -c -o /tmp/vorynex-live.test ./engine/enforce/live/
	sudo env VORYNEX_BPF_OBJECT=$(CURDIR)/engine/enforce/live/bpf/live.bpf.o \
		/tmp/vorynex-live.test -test.run TestLSMCapabilityEnforcement -test.v

# Defensive proof-of-value lab. Needs node + python3; the interim engine also
# needs go + bwrap + strace. See docs/SECURITY_TESTING.md.
lab:
	cd tests/security-lab && ./run-lab.sh

# Refresh the local RepoSpine context index used by AI agents (gitignored).
# Install once: npm i -g repospine-cli
context:
	@command -v atlas >/dev/null 2>&1 || { echo "atlas not installed — run: npm i -g repospine-cli"; exit 1; }
	atlas update --repo $(CURDIR)

# Containment proof: arm A (bare) vs arm C (Vorynex Tier 0). Loopback + decoys.
# PROOF_AUTHORIZED=1 is set here because the target is this repo's own fixture.
proof:
	PROOF_AUTHORIZED=1 tests/proof/run-proof.sh

# P3: the same comparison against a real third-party app (DVWS-node) in Docker.
# Pulls ~2.5 GB on first run, so it is not part of CI. The Vorynex Tier 1 column
# needs root (it attaches BPF hooks to the running container's cgroup).
proof-real:
	tests/proof/real/run-real.sh

# P4: overhead of the enforcement tiers vs the workload bare and vs a WAF in the
# request path. Interleaved rounds, open-loop load, paired deltas.
bench:
	tests/proof/bench/run-bench.sh

# End-to-end acceptance: build -> install -> capability report -> observe ->
# generate policy -> protect -> attack contained (and control landed) ->
# rollback -> off -> control-plane ingestion. Needs no root and no Docker.
e2e:
	tests/e2e/run-e2e.sh

# Release tarballs for $(PLATFORMS) with checksums. The Tier 1 BPF object is
# bundled when clang is available; without it the release is Tier 0 only.
# -p 1 keeps peak memory down: cross-building several platforms at the default
# parallelism gets OOM-killed on a small CI box.
release:
	@rm -rf dist && mkdir -p dist
	@-$(MAKE) bpf >/dev/null 2>&1 || echo "note: clang unavailable — Tier 1 object not bundled"
	@for p in $(PLATFORMS); do \
		os=$${p%%/*}; arch=$${p##*/}; \
		name=vorynex_$(VERSION)_$${os}_$${arch}; \
		dir=dist/$$name; \
		mkdir -p "$$dir/packaging/systemd" "$$dir/cloud"; \
		echo "building $$name"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -p 1 -trimpath -ldflags "$(LDFLAGS)" -o "$$dir/vorynex" ./cmd/vorynex || exit 1; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -p 1 -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o "$$dir/vorynex-cloud" ./cmd/vorynex-cloud || exit 1; \
		cp README.md LICENSE THIRD_PARTY_NOTICES.md VERSION install.sh "$$dir/"; \
		cp packaging/systemd/*.service "$$dir/packaging/systemd/"; \
		cp -r cloud/dashboard "$$dir/cloud/"; \
		if [ -f engine/enforce/live/bpf/live.bpf.o ]; then \
			mkdir -p "$$dir/packaging/bpf"; \
			cp engine/enforce/live/bpf/live.bpf.o "$$dir/packaging/bpf/"; \
		fi; \
		tar -C dist -czf "dist/$$name.tar.gz" "$$name"; \
		rm -rf "$$dir"; \
	done
	@cd dist && sha256sum *.tar.gz > checksums.txt && cat checksums.txt

# Install into $(PREFIX) from this checkout (no tarball). Uses the same script a
# user runs, so the install path is exercised every time.
install:
	PREFIX=$(PREFIX) ./install.sh

clean:
	go clean ./...
	rm -rf tests/security-lab/evidence tests/proof/evidence tests/proof/evidence-real tests/proof/evidence-bench
