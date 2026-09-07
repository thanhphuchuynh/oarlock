SHELL := /bin/sh

GO ?= go
NPM ?= npm
GOCACHE ?= $(CURDIR)/.cache/go-build

OARLOCKD := oarlockd
OARLOCK_AGENT := oarlock-agent
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
# when it misbehaves at 03:00. Both variables already existed and nothing had ever set them.
RELEASE_LD_SERVER := -s -w -X github.com/oarlock/oarlock/cmd/oarlockd/app.Version=$(RELEASE_VERSION)
RELEASE_LD_AGENT := -s -w -X main.version=$(RELEASE_VERSION)
ANDROID_HOME ?= $(HOME)/Library/Android/sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/27.1.12297006
MOBILE_BIN := $(CURDIR)/.cache/mobile/bin
ANDROID_BINDINGS := android/bindings
ANDROID_APP := android/agent-app
ANDROID_AAR := $(ANDROID_APP)/app/libs/oarlockagent.aar
ANDROID_APK := $(ANDROID_APP)/app/build/outputs/apk/debug/app-debug.apk
ANDROID_DIST := dist/oarlock-agent-android-arm64-debug.apk
ANDROID_BIN := dist/oarlock-agent-android-arm64

.PHONY: help build binaries ui typecheck test vet check clean release release-list landing landing-build landing-preview landing-lan documents local-config local-server demo-url demo-reset demo-server demo-seed-device demo-seed-permissions demo-agent dev-ui android-tools android-test android-aar android-apk android-binary android-check android-key android-conf android-push android-reverse android-register android-agent android-up

help:
	@printf '%s\n' \
		'Targets:' \
		'  make build        Build Go binaries and embedded admin UI' \
		'  make binaries     Build ./oarlockd and ./oarlock-agent' \
		'  make ui           Build embedded admin UI assets' \
		'  make check        Run typecheck, UI build, Go tests, and go vet' \
		'  make release      Build oarlockd and oarlock-agent for every supported machine' \
		'  make release-list Show that matrix without building it' \
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
		'  make documents    Re-render the document sheets from the Markdown' \
		'  make landing-lan  Serve the sheets to this network, on this LAN address' \
		'  make android-apk  Build the standalone ARM64 Android/VR agent APK' \
		'  make android-binary  Build the ARM64 agent binary for a system image'

build: binaries

binaries: ui
	GOCACHE=$(GOCACHE) $(GO) build -o $(OARLOCKD) ./cmd/oarlockd
	GOCACHE=$(GOCACHE) $(GO) build -o $(OARLOCK_AGENT) ./cmd/oarlock-agent

ui:
	$(NPM) run build:ui

# Every machine type, both binaries, stamped and stripped.
#
# Depends on `ui` so the console embedded in each gateway is the current one. That makes a
# release need the frontend toolchain, which is deliberate: `go build` alone still works on
# a clean checkout thanks to the .gitkeep in the embed directory, but shipping that to
# somebody means shipping a gateway whose console is an empty page.
release: ui
	@rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)
	@printf 'oarlock %s\n\n' '$(RELEASE_VERSION)'
	@set -e; \
	for spec in $(addsuffix :both,$(RELEASE_BOTH)) \
	            $(addsuffix :server,$(RELEASE_SERVER_ONLY)) \
	            $(addsuffix :agent,$(RELEASE_AGENT_ONLY)); do \
	  pair=$${spec%:*}; which=$${spec##*:}; os=$${pair%/*}; arch=$${pair#*/}; \
	  goarm=; label=$$arch; \
	  if [ "$$arch" = arm ]; then goarm=7; label=armv7; fi; \
	  ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
	  case $$which in \
	    both) cmds='oarlockd oarlock-agent';; \
	    server) cmds='oarlockd';; \
	    agent) cmds='oarlock-agent';; \
	  esac; \
	  for cmd in $$cmds; do \
	    if [ "$$cmd" = oarlockd ]; then ld='$(RELEASE_LD_SERVER)'; else ld='$(RELEASE_LD_AGENT)'; fi; \
	    out=$(RELEASE_DIR)/$$cmd-$$os-$$label$$ext; \
	    GOOS=$$os GOARCH=$$arch GOARM=$$goarm CGO_ENABLED=0 GOCACHE=$(GOCACHE) \
	      $(GO) build -trimpath -ldflags="$$ld" -o $$out ./cmd/$$cmd; \
	    printf '  %-38s %6s\n' "$${out#$(RELEASE_DIR)/}" "$$(du -h $$out | cut -f1)"; \
	  done; \
	done
	@cd $(RELEASE_DIR) && \
	  { command -v sha256sum >/dev/null 2>&1 && sha256sum * > SHA256SUMS || shasum -a 256 * > SHA256SUMS; }
	@printf '\n%s binaries in %s, and SHA256SUMS beside them.\n' \
	  "$$(ls -1 $(RELEASE_DIR) | grep -cv SHA256SUMS)" '$(RELEASE_DIR)'
	@printf 'Checksums, not signatures: they prove a download is intact, not that it came\n'
	@printf 'from you. Signing and an SBOM are named as not-built in the threat model.\n'

# The matrix, without spending four minutes to see it. GOARM=7 is explicit because an
# armv7 binary dies with SIGILL on armv6 and the filename is the only warning a reader gets.
release-list:
	@printf 'version  %s\n' '$(RELEASE_VERSION)'
	@printf 'both     %s\n' '$(RELEASE_BOTH)'
	@printf 'server   %s  (agent: no Setsid on windows)\n' '$(RELEASE_SERVER_ONLY)'
	@printf 'agent    %s  (gateway: sqlite driver does not build)\n' '$(RELEASE_AGENT_ONLY)'
	@printf 'excluded android/amd64  (needs cgo linking; these builds are CGO_ENABLED=0)\n'

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
	rm -f $(OARLOCKD) $(OARLOCK_AGENT)
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

# Sheets 2 and 3, rendered from the Markdown that is already the source of truth.
# Separate from landing-build so a documentation edit does not wait on a vite build.
documents:
	$(NPM) run documents

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
	printf 'sheet 1   http://%s:5181/\n' "$$addr"; \
	printf 'register  http://%s:5181/documents/\n' "$$addr"; \
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
		-ldflags='-s -w -extldflags=-Wl,-z,max-page-size=16384' \
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
		$(GO) build -trimpath -ldflags='-s -w' -o $(ANDROID_BIN) ./cmd/oarlock-agent
	@printf 'binary: %s\n' '$(CURDIR)/$(ANDROID_BIN)'
	@printf 'install: adb push %s /system/bin/oarlock-agent  (or bake it into the image)\n' '$(ANDROID_BIN)'

android-apk: android-aar
	cd $(ANDROID_APP) && ./gradlew --offline --no-daemon assembleDebug
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
