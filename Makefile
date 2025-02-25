PROJECT := ewc
APP     := rfc-test-runner
NAME    = $(PROJECT)-$(APP)

TERM_FLAGS ?= -ti

EXTRA_RUN_ARGS ?=

VERSION   ?= $(shell git describe --tags --abbrev=0)
CANDIDATE ?= "dev"
CONTAINER_DASHBOARD ?= "ewc_rfc_test_runner"
CONTAINER_REDIS ?= "redis"

CONTAINER_DEFAULT_RUN_FLAGS := \
	--rm $(TERM_FLAGS) \
	$(EXTRA_RUN_ARGS)

DOCKER_IMAGE := $(NAME)

.DEFAULT_GOAL := help
.PHONY: help
help:
	@echo "------------------------------------------------------------------------"
	@echo "EWC TEST RUNNER"
	@echo "------------------------------------------------------------------------"
	@grep -E '^[0-9a-zA-Z_/%\-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

run: ## Run locally for development purposes
	docker run \
		$(CONTAINER_DEFAULT_RUN_FLAGS) \
		-p 3000:3000 \
		--name "${CONTAINER_DASHBOARD}" \
		$(DOCKER_IMAGE):dev

redis-start: ## Run Redis container with persistence
	docker run \
		-d \
		--name ${CONTAINER_REDIS} \
		-p 6379:6379 \
		-v redis-data:/data \
		redis:latest \
		redis-server --appendonly yes

redis-stop: ## Stop Redis container
	docker stop ${CONTAINER_REDIS}
	docker rm ${CONTAINER_REDIS}

build: ## Builds the docker image
	docker build -t $(DOCKER_IMAGE):dev -f resources/docker/Dockerfile .
