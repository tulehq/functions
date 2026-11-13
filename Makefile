.PHONY: default fmt test test-e2e build lint image smoke push

define run
	@fail=0; \
		printf '➡️  make %-12s ' "$(1) ..."; \
		if out=$$($(MAKE) $(1) 2>&1); then \
			echo "✅"; \
		else \
			echo "❌"; \
			printf '%s\n' "$$out" | sed 's/^/    /'; \
			fail=1; \
		fi; \
	exit $$fail
endef

default:
	$(call run,lint)
	$(call run,test)
	$(call run,build)

fmt:
	golangci-lint fmt

test:
	go test ./...

test-e2e:
	go test -tags e2e -count=1 -timeout 15m ./test/e2e/...

build:
	go build -o build/tule-functions ./cmd

IMAGE   ?= ghcr.io/tulehq/functions
VERSION ?= dev

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

smoke: image
	test/smoke/run.sh $(IMAGE):$(VERSION)

push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .

lint:
	golangci-lint run
