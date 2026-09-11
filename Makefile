SHELL := /bin/sh

GO ?= go
NPM ?= npm
GOCACHE ?= $(CURDIR)/.cache/go-build

OARLOCKD := oarlockd
OARLOCK_AGENT := oarlock-agent
OARLOCKCTL := oarlockctl
DEMO_DIR := demo
DEMO_CONFIG := $(DEMO_DIR)/oarlock.yaml
LOCAL_CONFIG := $(DEMO_DIR)/oarlock.local.yaml
DEMO_DEVICE := treadmill-4821
DEMO_GATEWAY := ws://127.0.0.1:8443/ws/control
DEMO_SHELL := /bin/sh
DEMO_API := http://127.0.0.1:8443/api/v1
DEMO_TOKEN := dev-token-long-enough-for-the-check

MOBILE_VERSION := v0.0.0-20260821190718-4776eadac327

# ── release matrix ──────────────────────────────────────────────────────────────
#
# Not a wish list — every pair below was probed with a real cross-compile, and the three
# exclusions are recorded as what they are rather than left to fail at release time:
#
#   windows      agent only fails: creack/pty reaches for syscall.SysProcAttr.Setsid,
#                which Windows does not have. The gateway builds fine, so Windows gets a
#                server binary and no agent.
#   netbsd/amd64 gateway only fails: modernc.org/sqlite's generated netbsd/amd64 support
#                does not compile. The agent needs no database, so it ships and the
#                gateway does not.
#   android/amd64 neither: the toolchain demands external (cgo) linking, and these builds
#                are CGO_ENABLED=0 throughout. android/arm64 is unaffected and is the one
#                that matters for headsets.
#
# One asymmetry worth knowing before you copy a binary onto a device: every linux, freebsd,
# openbsd and netbsd output is `statically linked`, but android/arm64 comes out a
# dynamically linked PIE against bionic, because that is what GOOS=android does even with
# cgo off. It runs on Android and nowhere else — do not reach for it as a generic aarch64
# static binary. linux/arm64 is that.
#
# CGO_ENABLED=0 throughout is only possible because the SQLite driver is modernc.org/sqlite,
# which is pure Go. Swapping it for a cgo driver would take this matrix down to one row.
RELEASE_DIR ?= dist/release
RELEASE_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

RELEASE_BOTH ?= linux/amd64 linux/arm64 linux/arm linux/386 linux/riscv64 \
                linux/ppc64le linux/s390x darwin/amd64 darwin/arm64 \
                freebsd/amd64 freebsd/arm64 openbsd/amd64 android/arm64
RELEASE_SERVER_ONLY ?= windows/amd64 windows/arm64
RELEASE_AGENT_ONLY ?= netbsd/amd64

# A release binary that answers `dev` to -version is a binary nobody can tie to a commit
# when it misbehaves at 03:00. One ldflag, three binaries, same product number.
VERSION_LD := -X github.com/oarlock/oarlock/internal/buildinfo.Version=$(RELEASE_VERSION)
RELEASE_LD := -s -w $(VERSION_LD)

# npm / Android want MAJOR.MINOR.PATCH with no `v` and no git-describe junk.
PRODUCT_VERSION := $(shell printf '%s' '$(RELEASE_VERSION)' | awk '/^v?[0-9]+\.[0-9]+\.[0-9]+$$/ { sub(/^v/, ""); print }')
ANDROID_VERSION_NAME ?= $(if $(PRODUCT_VERSION),$(PRODUCT_VERSION),0.1.0)
ANDROID_VERSION_CODE ?= $(shell printf '%s' '$(ANDROID_VERSION_NAME)' | awk -F. '{print $$1*10000+$$2*100+$$3}')

# ── supply chain ────────────────────────────────────────────────────────────────
#
# There are two things a checksum file cannot do: say what is inside a binary, and say who
# built it. SHA256SUMS proves a download arrived intact and nothing more — anyone who can
# replace the binaries can replace the checksums sitting beside them. So: an SBOM per
# binary, and one signature over SHA256SUMS, which transitively covers every artefact
# listed in it, SBOMs included.
#
# Per *binary*, not per release, because the binaries genuinely differ — and along more than
# one axis. The 15 `oarlockd` outputs have five distinct dependency sets: 27 modules on
# linux/riscv64, 31 on darwin, freebsd, openbsd and windows, and three shapes in between.
# Off linux the sqlite driver reaches for go-isatty and go-strftime; on riscv64 it drops
# cpuid and bigfft. `oarlock-agent` links 4 modules everywhere except linux/s390x, which
# links 5 — it is the one target that pulls in golang.org/x/sys.
#
# So a single release-wide SBOM would be wrong for 14 of those 15 gateways, and would tell
# an operator scanning the agent for CVEs that it contains SQLite and MinIO. It does not.
# An SBOM that overstates a binary is worse than no SBOM: it is a false statement in the
# one document a scanner will believe without checking.
#
# The tool is built once for this machine and then run with GOOS/GOARCH set per target.
# That is not decoration: `cyclonedx-gomod bin` reads the module list out of the binary
# itself, but stamps the purl qualifiers from its own environment. Run it unset and every
# artefact in the matrix is labelled `goos=darwin&goarch=arm64` — the machine that built
# it, not the machine it runs on.
SBOM_TOOL_VERSION ?= v1.12.0
MINISIGN_VERSION ?= v0.3.0
TOOLS_DIR := $(CURDIR)/.cache/tools
SBOM_TOOL := $(TOOLS_DIR)/cyclonedx-gomod
MINISIGN := $(TOOLS_DIR)/minisign

# The release signing key, outside the repository by default — and it has to stay outside.
# A private key in a working tree is one `git add -A` away from being public forever, and
# this repository has already had a stray signing key land in its root once. The signing
# targets check the path rather than trusting .gitignore to catch it.
RELEASE_SECKEY ?= $(HOME)/.minisign/oarlock.key
RELEASE_PUBKEY ?= $(HOME)/.minisign/oarlock.pub
ANDROID_HOME ?= $(HOME)/Library/Android/sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/27.1.12297006
MOBILE_BIN := $(CURDIR)/.cache/mobile/bin
ANDROID_BINDINGS := android/bindings
ANDROID_APP := android/agent-app
ANDROID_AAR := $(ANDROID_APP)/app/libs/oarlockagent.aar
ANDROID_APK := $(ANDROID_APP)/app/build/outputs/apk/debug/app-debug.apk
ANDROID_DIST := dist/oarlock-agent-android-arm64-debug.apk
ANDROID_BIN := dist/oarlock-agent-android-arm64

.PHONY: help build binaries ui typecheck test vet check clean release release-list release-sign release-verify release-keygen stamp-version landing landing-build landing-preview landing-lan documents local-config local-server demo-url demo-reset demo-server demo-seed-device demo-seed-permissions demo-agent dev-ui android-tools android-test android-aar android-apk android-binary android-check android-key android-conf android-push android-reverse android-register android-agent android-up

help:
	@printf '%s\n' \
		'Targets:' \
		'  make build        Build Go binaries and embedded admin UI' \
		'  make binaries     Build ./oarlockd, ./oarlock-agent and ./oarlockctl' \
		'  make ui           Build embedded admin UI assets' \
		'  make check        Run typecheck, UI build, Go tests, and go vet' \
		'  make release      Build oarlockd and oarlock-agent for every supported machine' \
		'  make release-list Show that matrix without building it' \
		'  make release-keygen Generate the release signing key, outside the repo' \
		'  make release-sign Sign SHA256SUMS with that key' \
		'  make release-verify Verify the signature and every checksum under it' \
		'  make test         Run Go tests and frontend tests' \
		'  make vet          Run go vet ./...' \
		'  make demo-url     Point demo/oarlock.yaml at the current LAN address' \
		'  make demo-reset   Remove demo/oarlock.db for a clean SQLite registry' \
		'  make demo-server  Start demo gateway with demo/oarlock.yaml' \
		'  make local-config Write demo/oarlock.local.yaml, a loopback-only copy' \
		'  make local-server Start the gateway on 127.0.0.1 only' \
		'  make demo-seed-device  Add treadmill-4821 to the demo SQLite registry' \
		'  make demo-seed-permissions  Add the demo grants to SQLite' \
		'  make demo-agent   Start demo oarlock-agent for treadmill-4821' \
		'  make dev-ui       Start Vite console dev server' \
		'  make landing      Serve the landing sheet source on :5180, live reload' \
		'  make landing-preview  Build it and serve the output on :5181' \
		'  make documents    Generate the Mintlify pages from the Markdown' \
		'  make landing-lan  Serve the landing sheet to this network, on this LAN address' \
		'  make android-apk  Build the standalone ARM64 Android/VR agent APK' \
		'  make android-binary  Build the ARM64 agent binary for a system image'

build: binaries

binaries: ui
	GOCACHE=$(GOCACHE) $(GO) build -ldflags='$(VERSION_LD)' -o $(OARLOCKD) ./cmd/oarlockd
	GOCACHE=$(GOCACHE) $(GO) build -ldflags='$(VERSION_LD)' -o $(OARLOCK_AGENT) ./cmd/oarlock-agent
	GOCACHE=$(GOCACHE) $(GO) build -ldflags='$(VERSION_LD)' -o $(OARLOCKCTL) ./cmd/oarlockctl

ui:
	$(NPM) run build:ui

# Every machine type, stamped and stripped. oarlockctl ships where oarlockd does, except
# android/arm64 (an operator CLI does not belong on a headset).
#
# Depends on `ui` so the console embedded in each gateway is the current one. That makes a
# release need the frontend toolchain, which is deliberate: `go build` alone still works on
# a clean checkout thanks to the .gitkeep in the embed directory, but shipping that to
# somebody means shipping a gateway whose console is an empty page.
stamp-version:
	node scripts/stamp-version.mjs '$(RELEASE_VERSION)'

release: ui $(SBOM_TOOL)
	@rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)
	@printf 'oarlock %s\n\n' '$(RELEASE_VERSION)'
	@if [ -n '$(PRODUCT_VERSION)' ]; then \
	  node scripts/stamp-version.mjs '$(RELEASE_VERSION)'; \
	else \
	  printf 'npm packages left at 0.0.0: %s is not MAJOR.MINOR.PATCH\n' '$(RELEASE_VERSION)'; \
	fi
	@set -e; \
	for spec in $(addsuffix :both,$(RELEASE_BOTH)) \
	            $(addsuffix :server,$(RELEASE_SERVER_ONLY)) \
	            $(addsuffix :agent,$(RELEASE_AGENT_ONLY)); do \
	  pair=$${spec%:*}; which=$${spec##*:}; os=$${pair%/*}; arch=$${pair#*/}; \
	  goarm=; label=$$arch; \
	  if [ "$$arch" = arm ]; then goarm=7; label=armv7; fi; \
	  ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
	  case $$which in \
	    both) cmds='oarlockd oarlock-agent oarlockctl';; \
	    server) cmds='oarlockd oarlockctl';; \
	    agent) cmds='oarlock-agent';; \
	  esac; \
	  for cmd in $$cmds; do \
	    if [ "$$cmd" = oarlockctl ] && [ "$$os" = android ]; then continue; fi; \
	    ld='$(RELEASE_LD)'; \
	    out=$(RELEASE_DIR)/$$cmd-$$os-$$label$$ext; \
	    GOOS=$$os GOARCH=$$arch GOARM=$$goarm CGO_ENABLED=0 GOCACHE=$(GOCACHE) \
	      $(GO) build -trimpath -ldflags="$$ld" -o $$out ./cmd/$$cmd; \
	    GOOS=$$os GOARCH=$$arch $(SBOM_TOOL) bin -json -output-version 1.6 \
	      -version '$(RELEASE_VERSION)' -output $$out.cdx.json $$out; \
	    printf '  %-38s %6s  %2s deps\n' "$${out#$(RELEASE_DIR)/}" \
	      "$$(du -h $$out | cut -f1)" "$$(( $$(grep -c '"purl"' $$out.cdx.json) - 1 ))"; \
	  done; \
	done
	@cd $(RELEASE_DIR) && \
	  { command -v sha256sum >/dev/null 2>&1 && sha256sum * > SHA256SUMS || shasum -a 256 * > SHA256SUMS; }
	@printf '\n%s binaries in %s, an SBOM beside each, and SHA256SUMS over the lot.\n' \
	  "$$(ls -1 $(RELEASE_DIR) | grep -cvE 'SHA256SUMS|[.]cdx[.]json$$')" '$(RELEASE_DIR)'
	@printf '\nUnsigned. SHA256SUMS proves a download is intact, not that it came from you:\n'
	@printf 'whoever can replace the binaries can replace the checksums beside them. Run\n'
	@printf '`make release-sign` to sign it — `make release-keygen` first if you have no key.\n'

# The matrix, without spending four minutes to see it. GOARM=7 is explicit because an
# armv7 binary dies with SIGILL on armv6 and the filename is the only warning a reader gets.
release-list:
	@printf 'version  %s\n' '$(RELEASE_VERSION)'
	@printf 'both     %s\n' '$(RELEASE_BOTH)'
	@printf 'server   %s  (agent: no Setsid on windows)\n' '$(RELEASE_SERVER_ONLY)'
	@printf 'agent    %s  (gateway: sqlite driver does not build)\n' '$(RELEASE_AGENT_ONLY)'
	@printf 'excluded android/amd64  (needs cgo linking; these builds are CGO_ENABLED=0)\n'

# ── the two tools, built once into .cache/tools ─────────────────────────────────
#
# Pinned, and built rather than downloaded as a binary: the whole point of this section is
# provenance, so fetching an unverified executable to produce a provenance document would
# be a joke at its own expense. `go install pkg@version` verifies against the checksum
# database, which is a real check that costs nothing.
#
# cyclonedx-gomod v1.12 needs Go 1.26 to compile itself. The product stays on 1.25.
# GOTOOLCHAIN=auto lets `go install` fetch that toolchain; CI sets GOTOOLCHAIN=local,
# which is why a release on 1.25 died with `requires go >= 1.26.0`.
$(SBOM_TOOL):
	@mkdir -p $(TOOLS_DIR)
	@printf 'building cyclonedx-gomod %s, once\n' '$(SBOM_TOOL_VERSION)'
	@GOBIN=$(TOOLS_DIR) GOCACHE=$(GOCACHE) GOTOOLCHAIN=auto $(GO) install \
	  github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(SBOM_TOOL_VERSION)

$(MINISIGN):
	@mkdir -p $(TOOLS_DIR)
	@printf 'building minisign %s, once\n' '$(MINISIGN_VERSION)'
	@GOBIN=$(TOOLS_DIR) GOCACHE=$(GOCACHE) $(GO) install \
	  aead.dev/minisign/cmd/minisign@$(MINISIGN_VERSION)

# Ed25519 over SHA256SUMS, in minisign's format, so a downloader verifies with whichever
# minisign they already have rather than a tool of ours. One signature covers the release:
# every binary and every SBOM is named in the file being signed.
#
# The key is encrypted at rest and this prompts for its password. That is deliberate — a
# release is a thing a person decides to make, and an unattended signing key is a signing
# key an intruder also has.
release-sign: $(MINISIGN)
	@test -f '$(RELEASE_DIR)/SHA256SUMS' || { \
	  printf 'No %s/SHA256SUMS — run `make release` first.\n' '$(RELEASE_DIR)' >&2; exit 1; }
	@case '$(RELEASE_SECKEY)' in \
	  '$(CURDIR)'|'$(CURDIR)'/*) \
	    printf 'Refusing: RELEASE_SECKEY is inside the working tree.\n' >&2; \
	    printf 'A private key here is one `git add -A` from being public forever, and\n' >&2; \
	    printf 'this repository has had a stray signing key in its root once already.\n' >&2; \
	    exit 1;; \
	esac
	@test -f '$(RELEASE_SECKEY)' || { \
	  printf 'No signing key at %s.\n' '$(RELEASE_SECKEY)' >&2; \
	  printf '`make release-keygen` makes one.\n' >&2; exit 1; }
	$(MINISIGN) -S -s '$(RELEASE_SECKEY)' -m '$(RELEASE_DIR)/SHA256SUMS' \
	  -c 'oarlock $(RELEASE_VERSION)' \
	  -t 'oarlock $(RELEASE_VERSION) — checksums for every artefact in this release'
	@printf '\nSigned: %s/SHA256SUMS.minisig\n' '$(RELEASE_DIR)'
	@printf 'Ship the .minisig beside SHA256SUMS. The public key belongs somewhere a\n'
	@printf 'downloader can reach without trusting the download: SECURITY.md, not the\n'
	@printf 'release directory, which an attacker replacing binaries also controls.\n'

# What a downloader does, run against your own release so it is known to work before
# somebody else is the first to try it.
release-verify: $(MINISIGN)
	@test -f '$(RELEASE_DIR)/SHA256SUMS.minisig' || { \
	  printf 'Not signed. `make release-sign` signs it.\n' >&2; exit 1; }
	@test -f '$(RELEASE_PUBKEY)' || { \
	  printf 'No public key at %s.\n' '$(RELEASE_PUBKEY)' >&2; exit 1; }
	$(MINISIGN) -V -p '$(RELEASE_PUBKEY)' -m '$(RELEASE_DIR)/SHA256SUMS'
	@cd $(RELEASE_DIR) && \
	  { command -v sha256sum >/dev/null 2>&1 && sha256sum -c SHA256SUMS >/dev/null \
	    || shasum -a 256 -c SHA256SUMS >/dev/null; } && \
	  printf '%s artefacts match the checksums that signature covers.\n' \
	    "$$(wc -l < SHA256SUMS | tr -d ' ')"

# Generating a key is a one-time act with a long tail: every signature you ever make is
# tied to it, so this refuses to overwrite one that exists rather than quietly orphaning
# every signature already in the world.
release-keygen: $(MINISIGN)
	@case '$(RELEASE_SECKEY)' in \
	  '$(CURDIR)'|'$(CURDIR)'/*) \
	    printf 'Refusing: RELEASE_SECKEY is inside the working tree.\n' >&2; \
	    printf 'A private key here is one `git add -A` from being public forever, and\n' >&2; \
	    printf 'this repository has had a stray signing key in its root once already.\n' >&2; \
	    exit 1;; \
	esac
	@if [ -f '$(RELEASE_SECKEY)' ]; then \
	  printf 'A key already exists at %s — refusing to overwrite it.\n' '$(RELEASE_SECKEY)' >&2; \
	  printf 'Overwriting orphans every signature it has already made.\n' >&2; \
	  exit 1; \
	fi
	@mkdir -p "$$(dirname '$(RELEASE_SECKEY)')"
	$(MINISIGN) -G -s '$(RELEASE_SECKEY)' -p '$(RELEASE_PUBKEY)'
	@printf '\nPublish this public key where a downloader finds it independently of the\n'
	@printf 'artefacts — SECURITY.md and the landing page:\n\n'
	@cat '$(RELEASE_PUBKEY)'

typecheck:
	$(NPM) run typecheck

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...
	$(NPM) test

vet:
	GOCACHE=$(GOCACHE) $(GO) vet ./...

check: typecheck ui
	GOCACHE=$(GOCACHE) $(GO) test ./...
	GOCACHE=$(GOCACHE) $(GO) vet ./...

clean:
	rm -f $(OARLOCKD) $(OARLOCK_AGENT) $(OARLOCKCTL)
	rm -rf dist web/dist landing/dist .cache/go-build

# The address a device dials back on has to be reachable *by the device*, so for a phone
# on the LAN it is this machine's LAN address — which DHCP changes without asking. A stale
# value looks like a device that never answers: the gateway logs `device_offline` and the
# agent logs `connection refused` to an address that used to be here.
demo-url:
	@addr=$$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null); 	if [ -z "$$addr" ]; then echo "no LAN address on en0/en1"; exit 1; fi; 	current=$$(sed -n 's|^url: ws://\([^:]*\):.*|\1|p' $(DEMO_CONFIG)); 	if [ "$$current" = "$$addr" ]; then printf 'demo url is already ws://%s:8443\n' "$$addr"; exit 0; fi; 	sed -i '' "s|^url: ws://.*|url: ws://$$addr:8443|" $(DEMO_CONFIG); 	printf 'demo url: ws://%s:8443 (was %s) — restart the gateway, and update the APK\n' "$$addr" "$$current"

# A loopback-only gateway, for working on this machine with nothing else involved.
#
# The only thing that has to differ from the demo config is `url`, and it is the one
# thing that matters: it is the address the *agent* dials for the session leg, so a LAN
# address left in it from the last phone session makes a local run fail as though the
# device never answered. Generated rather than committed, because demo/ is ignored and a
# second config to keep in step with the first is a config that drifts.
local-config:
	@sed 's|^url: ws://.*|url: ws://127.0.0.1:8443|' $(DEMO_CONFIG) > $(LOCAL_CONFIG)
	@printf 'wrote %s (url: ws://127.0.0.1:8443)\n' '$(LOCAL_CONFIG)'

local-server: local-config
	cd $(DEMO_DIR) && ../$(OARLOCKD) -config ./oarlock.local.yaml

demo-reset:
	rm -f $(DEMO_DIR)/oarlock.db

demo-server:
	cd $(DEMO_DIR) && ../$(OARLOCKD) -config ./oarlock.yaml

demo-seed-device:
	@body="{\"id\":\"$(DEMO_DEVICE)\",\"platform\":\"android\",\"mode\":\"dispatch\",\"keys\":[\"$$(cat $(DEMO_DIR)/device.key.pub)\"],\"profiles\":[\"shell\"]}"; \
	curl -fsS -X POST $(DEMO_API)/devices \
		-H 'Authorization: Bearer $(DEMO_TOKEN)' \
		-H 'Content-Type: application/json' \
		-d "$$body" || \
	curl -fsS -X PUT $(DEMO_API)/devices/$(DEMO_DEVICE) \
		-H 'Authorization: Bearer $(DEMO_TOKEN)' \
		-H 'Content-Type: application/json' \
		-d "$$body"
	@printf '\n'

demo-seed-permissions:
	@set -eu; \
	upsert() { \
		id="$$1"; body="$$2"; \
		curl -fsS -X POST $(DEMO_API)/permissions \
			-H 'Authorization: Bearer $(DEMO_TOKEN)' -H 'Content-Type: application/json' -d "$$body" >/dev/null || \
		curl -fsS -X PUT $(DEMO_API)/permissions/$$id \
			-H 'Authorization: Bearer $(DEMO_TOKEN)' -H 'Content-Type: application/json' -d "$$body" >/dev/null; \
	}; \
	upsert operator-shell '{"id":"operator-shell","name":"Operator shell","principals":["*@oncall.example.com","admin@mail.com"],"devices":["treadmill-*","samsung-s23"],"actions":["shell","exec"],"effect":"allow","enabled":true}'; \
	upsert sql-explorer '{"id":"sql-explorer","name":"SQL Explorer","principals":["admin@mail.com"],"devices":["gateway"],"actions":["sql:read"],"effect":"allow","enabled":true}'; \
	upsert gateway-admin '{"id":"gateway-admin","name":"Gateway administrator","principals":["admin@mail.com"],"devices":["gateway"],"actions":["admin:permissions"],"effect":"allow","enabled":true}'; \
	upsert fleet-admin '{"id":"fleet-admin","name":"Fleet administrator","principals":["admin@mail.com"],"devices":["*"],"actions":["admin:devices","admin:kill"],"effect":"allow","enabled":true}'; \
	upsert contractor-shell '{"id":"contractor-shell","name":"Contractor shell","principals":["contractor@partner.example.com"],"devices":["treadmill-4821"],"actions":["shell"],"effect":"allow","max_duration":"15m","idle":"2m","ttl":"10s","enabled":true}'; \
	upsert auditor-read '{"id":"auditor-read","name":"Audit access","principals":["auditor@example.com"],"devices":["*"],"actions":["replay","observe"],"effect":"allow","enabled":true}'; \
	upsert deny-pci '{"id":"deny-pci","name":"PCI change control","principals":["*"],"devices":["*"],"tags":{"pci_scope":"true"},"actions":["*"],"effect":"deny","reason":"PCI-scoped devices need a change ticket","enabled":true}'; \
	printf '%s\n' 'Demo permissions are present in SQLite.'

demo-agent:
	cd $(DEMO_DIR) && ../$(OARLOCK_AGENT) \
		-gateway $(DEMO_GATEWAY) \
		-device $(DEMO_DEVICE) \
		-key ./device.key \
		-shell $(DEMO_SHELL) \
		-insecure-skip-pin

dev-ui:
	$(NPM) run dev:ui

# The landing sheet. Two servers because they answer different questions: `landing`
# is the one to edit against, `landing-preview` is the one to trust, because it
# serves the built bytes a host would serve rather than the source vite rewrites on
# the way out.
landing:
	$(NPM) run landing

landing-build:
	$(NPM) run build:landing

landing-preview:
	$(NPM) run preview:landing

# Mintlify pages, split from the Markdown that is already the source of truth.
documents:
	$(NPM) run docs:gen

# The sheets, readable by other machines on this network.
#
# Bound to *this* LAN address rather than 0.0.0.0. The address is already known — the
# target has to print it to be useful — and binding it explicitly means one interface
# is listening instead of every interface this machine happens to have, which on a
# laptop includes a VPN tunnel and whatever network it joined last. `pnpm
# preview:landing:lan` on its own still takes 0.0.0.0, for a container that needs it.
#
# Nothing here is authenticated. Anyone who can reach the address can read the sheets,
# which is the point, and is also the whole of the security model: stop the server.
landing-lan:
	@addr=$$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null); \
	if [ -z "$$addr" ]; then echo 'no LAN address on en0/en1'; exit 1; fi; \
	printf 'sheet     http://%s:5181/\n' "$$addr"; \
	printf 'docs      http://127.0.0.1:3000/  (pnpm docs)\n'; \
	printf 'readable by every host on this network until you stop it (ctrl-c)\n\n'; \
	OARLOCK_DOCS_HOST=$$addr $(NPM) run preview:landing:lan

android-tools:
	mkdir -p $(MOBILE_BIN)
	GOBIN=$(MOBILE_BIN) $(GO) install golang.org/x/mobile/cmd/gomobile@$(MOBILE_VERSION)
	GOBIN=$(MOBILE_BIN) $(GO) install golang.org/x/mobile/cmd/gobind@$(MOBILE_VERSION)

android-test:
	cd $(ANDROID_BINDINGS) && GOCACHE=$(GOCACHE) $(GO) test ./...

android-aar: android-tools android-test
	mkdir -p $(dir $(ANDROID_AAR))
	cd $(ANDROID_BINDINGS) && \
		PATH=$(MOBILE_BIN):$$PATH ANDROID_HOME=$(ANDROID_HOME) ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) \
		$(MOBILE_BIN)/gomobile bind -target=android/arm64 -androidapi 26 \
		-javapkg dev.oarlock.mobile -trimpath \
		-ldflags='$(RELEASE_LD) -extldflags=-Wl,-z,max-page-size=16384' \
		-o ../../$(ANDROID_AAR) ./oarlockagent

# The agent as an ordinary binary for a device whose system image you control.
#
# No NDK and no gomobile: CGO_ENABLED=0 and this is the same source, the same flags and
# the same code path as the agent that runs on a server. One artifact to test.
#
# The cost of dropping cgo is DNS: Go's pure resolver reads /etc/resolv.conf, Android has
# none, and the fallback is 127.0.0.1:53 where nothing listens. Name the servers in the
# agent's config (`dns:`) or put an IP in the gateway URL.
android-binary:
	mkdir -p $(dir $(ANDROID_BIN))
	GOOS=android GOARCH=arm64 CGO_ENABLED=0 GOCACHE=$(GOCACHE) \
		$(GO) build -trimpath -ldflags='$(RELEASE_LD)' -o $(ANDROID_BIN) ./cmd/oarlock-agent
	@printf 'binary: %s\n' '$(CURDIR)/$(ANDROID_BIN)'
	@printf 'install: adb push %s /system/bin/oarlock-agent  (or bake it into the image)\n' '$(ANDROID_BIN)'

android-apk: android-aar
	cd $(ANDROID_APP) && ./gradlew --offline --no-daemon assembleDebug \
		-PversionName=$(ANDROID_VERSION_NAME) -PversionCode=$(ANDROID_VERSION_CODE)
	mkdir -p $(dir $(ANDROID_DIST))
	install -m 0644 $(ANDROID_APK) $(ANDROID_DIST)
	@printf 'APK: %s\n' '$(CURDIR)/$(ANDROID_DIST)'

# ── the local loop ───────────────────────────────────────────────────────────────────
#
# Gateway on this machine, agent on a real Android machine over adb, MDM talking to the
# gateway's API. This is a development loop on a desk; none of it is how a fleet gets
# provisioned.
#
# The device reaches the gateway through `adb reverse`, not over the LAN. That is the
# whole trick, and it removes three separate things that otherwise go wrong: no LAN
# address to chase when DHCP moves, no `dns:` config because the URL is an IP literal,
# and no dependency on the two machines sharing a network. The tunnel is USB.

ADB ?= adb
# The device's id in the registry. Defaults to the adb serial, so one machine has one
# identity across adb, the Oarlock registry and the MDM — which is what makes the MDM
# able to name a device to the gateway without a mapping table.
ANDROID_DEVICE ?=
ANDROID_REMOTE := /data/local/tmp/oarlock
ANDROID_KEY := $(DEMO_DIR)/android-device.key
ANDROID_CONF := $(DEMO_DIR)/agent.android.yaml
# Device-local ports the pushed agent will forward. Space-separated.
# 5555 is adbd, which makes `adb connect` work through the gateway.
ANDROID_FORWARD_PORTS ?= 3000 5555

# adb-serial resolves the device id once, so every target below agrees on it.
ADB_SERIAL = $$(if [ -n '$(ANDROID_DEVICE)' ]; then printf '%s' '$(ANDROID_DEVICE)'; else $(ADB) get-serialno; fi)

android-check:
	@$(ADB) get-state >/dev/null 2>&1 || { \
		printf 'no device: plug one in, enable USB debugging, or `adb connect <host>:5555`\n'; \
		$(ADB) devices -l; exit 1; }
	@printf 'device: %s\n' "$(ADB_SERIAL)"

# The key is generated here rather than on the device so the public half can be seeded
# into the registry in the same breath. The agent exits after writing it.
# A file rule, so the chain works from a clean checkout. `binaries` is phony and does
# not teach make that this file has a recipe.
$(OARLOCK_AGENT):
	GOCACHE=$(GOCACHE) $(GO) build -o $@ ./cmd/oarlock-agent

android-key: $(OARLOCK_AGENT)
	@if [ -f $(ANDROID_KEY) ]; then printf 'key exists: %s\n' '$(ANDROID_KEY)'; else \
		./$(OARLOCK_AGENT) -generate-key -key $(ANDROID_KEY) >/dev/null; \
		test -f $(ANDROID_KEY) && printf 'key: %s\n' '$(ANDROID_KEY)'; fi

android-conf: android-key
	@printf '%s\n' \
		'# Generated by `make android-conf`. The gateway is reached through `adb reverse`,' \
		'# so 127.0.0.1 here is this device'"'"'s own loopback, forwarded to the Mac over USB.' \
		'gateway: ws://127.0.0.1:8443/ws/control' \
		"device: $(ADB_SERIAL)" \
		"key: $(ANDROID_REMOTE)/device.key" \
		'shell: /system/bin/sh' \
		'# Local loop only. A real deployment pins the gateway key; see android/system/agent.conf.example.' \
		'insecure_skip_pin: true' \
		'exec:' \
		'  - ["/system/bin/getprop", "ro.build.version.release"]' \
		'  - ["/system/bin/getprop", "ro.serialno"]' \
		'  - ["/system/bin/pm", "list", "packages", "-3"]' \
		'  - ["/system/bin/dumpsys", "battery"]' \
		'file_root: /data/local/tmp/oarlock/files' \
		'file_writable: true' \
		'# Device-local ports reachable with `ssh -L 8080:localhost:3000 <device>@gateway -N`.' \
		'# Dialled on 127.0.0.1 only. Override with ANDROID_FORWARD_PORTS="3000 5555".' \
		'forward_ports:' \
		$(foreach p,$(ANDROID_FORWARD_PORTS),'  - $(p)' ) \
		> $(ANDROID_CONF)
	@printf 'conf: %s (device %s)\n' '$(ANDROID_CONF)' "$(ADB_SERIAL)"

android-push: android-check android-binary android-conf
	$(ADB) shell mkdir -p $(ANDROID_REMOTE)/files
	$(ADB) push $(ANDROID_BIN) $(ANDROID_REMOTE)/oarlock-agent
	$(ADB) push $(ANDROID_CONF) $(ANDROID_REMOTE)/agent.yaml
	$(ADB) push $(ANDROID_KEY) $(ANDROID_REMOTE)/device.key
	$(ADB) shell chmod 0700 $(ANDROID_REMOTE)/oarlock-agent
	$(ADB) shell chmod 0600 $(ANDROID_REMOTE)/device.key
	@printf 'pushed to %s\n' '$(ANDROID_REMOTE)'

# The reverse tunnel has to be re-established after every reconnect, so it is its own
# target and every run target depends on it.
android-reverse: android-check
	$(ADB) reverse tcp:8443 tcp:8443
	@printf 'reverse: device 127.0.0.1:8443 -> this machine 8443\n'

# persistent, not dispatch: the agent started by `make android-agent` holds a control
# channel open for as long as the adb shell lives, so there is no doorbell to ring and
# no dispatcher to configure. A fleet device is `dispatch`; this one is a process on a desk.
android-register: android-key
	@set -eu; dev="$(ADB_SERIAL)"; \
	body="{\"id\":\"$$dev\",\"platform\":\"android\",\"mode\":\"persistent\",\"keys\":[\"$$(cat $(ANDROID_KEY).pub)\"],\"profiles\":[\"shell\",\"exec\",\"file\"]}"; \
	curl -fsS -X POST $(DEMO_API)/devices \
		-H 'Authorization: Bearer $(DEMO_TOKEN)' -H 'Content-Type: application/json' -d "$$body" >/dev/null 2>&1 || \
	curl -fsS -X PUT $(DEMO_API)/devices/$$dev \
		-H 'Authorization: Bearer $(DEMO_TOKEN)' -H 'Content-Type: application/json' -d "$$body" >/dev/null; \
	printf 'registered: %s (shell, exec, file)\n' "$$dev"

android-agent: android-reverse
	$(ADB) shell $(ANDROID_REMOTE)/oarlock-agent -config $(ANDROID_REMOTE)/agent.yaml

# One command from a plugged-in machine to a registered, connected device.
android-up: android-push android-register
	@printf '\nnow run, in another terminal:\n  make android-agent\n'
