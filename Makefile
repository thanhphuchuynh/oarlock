SHELL := /bin/sh

GO ?= go
NPM ?= npm
GOCACHE ?= $(CURDIR)/.cache/go-build

OARLOCKD := oarlockd
OARLOCK_AGENT := oarlock-agent
DEMO_DIR := demo
DEMO_CONFIG := $(DEMO_DIR)/oarlock.yaml
DEMO_DEVICE := treadmill-4821
DEMO_GATEWAY := ws://127.0.0.1:8443/ws/control
DEMO_SHELL := /bin/sh
DEMO_API := http://127.0.0.1:8443/api/v1
DEMO_TOKEN := dev-token-long-enough-for-the-check

MOBILE_VERSION := v0.0.0-20260821190718-4776eadac327
ANDROID_HOME ?= $(HOME)/Library/Android/sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/27.1.12297006
MOBILE_BIN := $(CURDIR)/.cache/mobile/bin
ANDROID_BINDINGS := android/bindings
ANDROID_APP := android/agent-app
ANDROID_AAR := $(ANDROID_APP)/app/libs/oarlockagent.aar
ANDROID_APK := $(ANDROID_APP)/app/build/outputs/apk/debug/app-debug.apk
ANDROID_DIST := dist/oarlock-agent-android-arm64-debug.apk
ANDROID_BIN := dist/oarlock-agent-android-arm64

.PHONY: help build binaries ui typecheck test vet check clean demo-reset demo-server demo-seed-device demo-seed-permissions demo-agent dev-ui android-tools android-test android-aar android-apk android-binary

help:
	@printf '%s\n' \
		'Targets:' \
		'  make build        Build Go binaries and embedded admin UI' \
		'  make binaries     Build ./oarlockd and ./oarlock-agent' \
		'  make ui           Build embedded admin UI assets' \
		'  make check        Run typecheck, UI build, Go tests, and go vet' \
		'  make test         Run Go tests and frontend tests' \
		'  make vet          Run go vet ./...' \
		'  make demo-reset   Remove demo/oarlock.db for a clean SQLite registry' \
		'  make demo-server  Start demo gateway with demo/oarlock.yaml' \
		'  make demo-seed-device  Add treadmill-4821 to the demo SQLite registry' \
		'  make demo-seed-permissions  Add the demo grants to SQLite' \
		'  make demo-agent   Start demo oarlock-agent for treadmill-4821' \
		'  make dev-ui       Start Vite console dev server' \
		'  make android-apk  Build the standalone ARM64 Android/VR agent APK' \
		'  make android-binary  Build the ARM64 agent binary for a system image'

build: binaries

binaries: ui
	GOCACHE=$(GOCACHE) $(GO) build -o $(OARLOCKD) ./cmd/oarlockd
	GOCACHE=$(GOCACHE) $(GO) build -o $(OARLOCK_AGENT) ./cmd/oarlock-agent

ui:
	$(NPM) run build:ui

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
	rm -rf dist web/dist .cache/go-build

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
	upsert operator-shell '{"id":"operator-shell","name":"Operator shell","principals":["*@oncall.example.com","phuc@example.com"],"devices":["treadmill-*","samsung-s23"],"actions":["shell","exec"],"effect":"allow","enabled":true}'; \
	upsert sql-explorer '{"id":"sql-explorer","name":"SQL Explorer","principals":["phuc@example.com"],"devices":["gateway"],"actions":["sql:read"],"effect":"allow","enabled":true}'; \
	upsert gateway-admin '{"id":"gateway-admin","name":"Gateway administrator","principals":["phuc@example.com"],"devices":["gateway"],"actions":["admin:permissions"],"effect":"allow","enabled":true}'; \
	upsert fleet-admin '{"id":"fleet-admin","name":"Fleet administrator","principals":["phuc@example.com"],"devices":["*"],"actions":["admin:devices","admin:kill"],"effect":"allow","enabled":true}'; \
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
