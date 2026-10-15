# Image to build/deploy.
IMG ?= ghcr.io/idaholab/malcolm-operator:latest

# Helm release used by helm-deploy.
CHART ?= charts/malcolm-operator
RELEASE ?= malcolm-operator
RELEASE_NAMESPACE ?= malcolm-operator-system

# Tool versions.
CONTROLLER_TOOLS_VERSION ?= v0.22.0
KUSTOMIZE_VERSION ?= v5.7.1
ENVTEST_K8S_VERSION ?= 1.37.0

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
KUSTOMIZE ?= $(LOCALBIN)/kustomize
ENVTEST ?= $(LOCALBIN)/setup-envtest
HELM ?= helm
MALCOLM_HELM_CHART ?= ../Malcolm-Helm/chart
KUBECTL ?= kubectl
CONTAINER_TOOL ?= docker

GOBIN = $(shell go env GOBIN)
ifeq (,$(GOBIN))
GOBIN = $(shell go env GOPATH)/bin
endif

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate the CRD and RBAC manifests (also copied into the Helm chart).
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd paths="./..." \
		output:crd:artifacts:config=config/crd/bases output:rbac:artifacts:config=config/rbac
	cp config/crd/bases/malcolm.idaholab.github.io_malcolms.yaml $(CHART)/files/crd.yaml
	cp config/rbac/role.yaml $(CHART)/files/manager-role.yaml

.PHONY: generate
generate: controller-gen ## Generate DeepCopy implementations.
	$(CONTROLLER_GEN) object paths="./api/..."

.PHONY: fmt
fmt: ## Run go fmt.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run unit and CRD tests (integration suites skip themselves).
	go test ./... -coverprofile cover.out

.PHONY: test-envtest
test-envtest: manifests generate setup-envtest ## Run the integration tests against a real kube-apiserver/etcd (Helm chart install too, if helm is installed).
	HELM_BIN="$$(command -v $(HELM) || true)" \
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./test/envtest/ -v

.PHONY: test-chart
test-chart: manifests ## Lint the Helm chart and check what it renders.
	$(HELM) lint --strict $(CHART)
	HELM_BIN="$$(command -v $(HELM))" go test ./test/chart/ -v

.PHONY: test-parity
test-parity: ## Compare rendered objects with `helm template` of the Malcolm Helm chart.
	HELM_BIN="$$(command -v $(HELM))" HELM_CHART=$(MALCOLM_HELM_CHART) go test ./test/parity/ -v

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build the manager binary.
	go build -o bin/manager ./cmd

.PHONY: run
run: manifests generate fmt vet ## Run the controller against the current kubeconfig.
	go run ./cmd

.PHONY: docker-build
docker-build: ## Build the manager image.
	$(CONTAINER_TOOL) build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the manager image.
	$(CONTAINER_TOOL) push $(IMG)

PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push a multi-arch image.
	- $(CONTAINER_TOOL) buildx create --name malcolm-operator-builder
	$(CONTAINER_TOOL) buildx use malcolm-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag $(IMG) .
	- $(CONTAINER_TOOL) buildx rm malcolm-operator-builder

.PHONY: build-installer
build-installer: manifests generate kustomize ## Write a single install manifest to dist/install.yaml.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

.PHONY: helm-deploy
helm-deploy: ## Install or upgrade the operator with the Helm chart (IMG sets the image).
	img='$(IMG)'; $(HELM) upgrade --install $(RELEASE) $(CHART) --namespace $(RELEASE_NAMESPACE) --create-namespace \
		--set image.repository="$${img%:*}" --set image.tag="$${img##*:}"

.PHONY: helm-undeploy
helm-undeploy: ## Uninstall the Helm release (the CRD and Malcolm resources are kept).
	$(HELM) uninstall $(RELEASE) --namespace $(RELEASE_NAMESPACE)

.PHONY: install
install: manifests kustomize ## Install the CRD into the current cluster.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply --server-side -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Remove the CRD (and every Malcolm resource) from the cluster.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy the operator to the current cluster.
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply --server-side -f -

.PHONY: undeploy
undeploy: kustomize ## Remove the operator from the cluster.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found -f -

##@ Tools

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(CONTROLLER_GEN) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: setup-envtest
setup-envtest: $(ENVTEST) ## Download setup-envtest locally.
$(ENVTEST): $(LOCALBIN)
	test -s $(ENVTEST) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.25

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally.
$(KUSTOMIZE): $(LOCALBIN)
	test -s $(KUSTOMIZE) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)
