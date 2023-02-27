SHELL := /bin/bash
.PHONY: help
primary := '\033[1;36m'
err := '\033[0;31m'
bold := '\033[1m'
clear := '\033[0m'

-include .env
export $(shell sed 's/=.*//' .env)
ifndef CI_BUILD_REF
CI_BUILD_REF=local
endif
ifeq ($(CI_BUILD_REF), local)
-include .env.local
export $(shell sed 's/=.*//' .env.local)
endif

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef BUILD_ENV
BUILD_ENV=development
endif
ifndef APP_ENV
APP_ENV=Dev
endif
ifndef RUNNER_NAME
RUNNER_NAME=$(shell basename $(shell pwd))
endif
ifndef TEST_HOSTNAME
TEST_HOSTNAME=jupiterbroadcasting.com
endif
ifndef TEST_SHA1SIG
TEST_SHA1SIG=091e8ea1b256a312962af6c140c0fbf079a407b3
endif

deps: ## install dependancies for development of this project
	pip install -U pip
	pip install -U -r requirements-dev.txt
	pip install -e .

setup: ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	detect-secrets audit .secrets.baseline

clean: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz

env:
	@echo -e $(bold)$(primary)BUILD_ENV$(clear) = $(BUILD_ENV)
	@echo -e $(bold)$(primary)APP_ENV$(clear) = $(APP_ENV)
	@echo -e $(bold)$(primary)CI_BUILD_REF$(clear) = $(CI_BUILD_REF)

output: env init
	@echo -e $(bold)$(primary)trivialscan_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_arn)
	@echo -e $(bold)$(primary)function_url$(clear) = $(shell terraform -chdir=plans output function_url)
	@echo -e $(bold)$(primary)trivialscan_role$(clear) = $(shell terraform -chdir=plans output trivialscan_role)
	@echo -e $(bold)$(primary)trivialscan_role_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_role_arn)
	@echo -e $(bold)$(primary)trivialscan_policy_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_policy_arn)

build: env ## makes the lambda zip archive
	python .$(BUILD_ENV)/build_yaml_descriptions.py
	./.$(BUILD_ENV)/bin/build-archive

tfinstall:
	curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
	sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"
	sudo apt-get update
	sudo apt-get install -y terraform
	terraform -install-autocomplete || true

init: env ## Runs tf init tf
	terraform -chdir=plans init -backend-config=${APP_ENV}-backend.conf -reconfigure -upgrade=true

plan: ## Runs tf validate and tf plan
	terraform -chdir=plans validate
	terraform -chdir=plans plan -no-color -out=.tfplan
	terraform -chdir=plans show --json .tfplan | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > plans/tfplan.json

apply: ## tf apply -auto-approve -refresh=true
	terraform -chdir=plans apply -auto-approve -refresh=true .tfplan

destroy: init ## tf destroy -auto-approve
	terraform -chdir=plans validate
	terraform -chdir=plans plan -destroy -no-color -out=.tfdestroy
	terraform -chdir=plans show --json .tfdestroy | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > plans/tfdestroy.json
	terraform -chdir=plans apply -auto-approve -destroy .tfdestroy

test-local: ## Prettier test outputs
	pre-commit run --all-files
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

unit-test: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

run-local: env ## A local server interfacing with Lambda URL
	uvicorn app:app --reload --reload-dir src --port 8080 --host 0.0.0.0

run-local-tls: env ## A local server interfacing with Lambda URL
	uvicorn app:app --reload --reload-dir src --port 443 --host 0.0.0.0 --ssl-keyfile .development/jager.key --ssl-certfile .development/jager.crt
# sudo tailscale cert --cert-file .development/jager.crt --key-file .development/jager.key jager.tail55052.ts.net
# (as sudo) echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf && sysctl --system

local-runner: ## local setup for a gitlab runner
	@docker volume create --name=gitlab-cache 2>/dev/null || true
	docker pull -q docker.io/gitlab/gitlab-runner:latest
	docker build -t $(RUNNER_NAME)/runner:${CI_BUILD_REF} -f Dockerfile-runner .
	@echo $(shell [ -z "${RUNNER_TOKEN}" ] && echo "RUNNER_TOKEN missing" )
	@docker run -d --rm \
		--name $(RUNNER_NAME) \
		-v "gitlab-cache:/cache:rw" \
		-v "/var/run/docker.sock:/var/run/docker.sock:rw" \
		-e RUNNER_TOKEN=${RUNNER_TOKEN} \
		$(RUNNER_NAME)/runner:${CI_BUILD_REF}
	@docker exec -ti $(RUNNER_NAME) gitlab-runner register --non-interactive \
		--tag-list 'jager' \
		--name $(RUNNER_NAME) \
		--request-concurrency 10 \
		--url https://gitlab.com/ \
		--registration-token '$(RUNNER_TOKEN)' \
		--cache-dir '/cache' \
		--executor shell

tail-aws-logs: ## Install using pipx install awscliv2
	awsv2 logs tail "/aws/lambda/$(shell sed -e 's/\(.*\)/\L\1/' <<< "${APP_ENV}")-trivialscan-api" --follow
