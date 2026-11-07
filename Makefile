.PHONY: build test vet fmt ci lab bpf bpf-test context proof clean

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

clean:
	go clean ./...
	rm -rf tests/security-lab/evidence tests/proof/evidence tests/proof/evidence-real
