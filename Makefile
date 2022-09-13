SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

primary := '\033[1;36m'
bold := '\033[1m'
clear := '\033[0m'

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

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

output:
	@echo -e $(bold)$(primary)trivialscan_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_arn)
	@echo -e $(bold)$(primary)function_url$(clear) = $(shell terraform -chdir=plans output function_url)
	@echo -e $(bold)$(primary)trivialscan_role$(clear) = $(shell terraform -chdir=plans output trivialscan_role)
	@echo -e $(bold)$(primary)trivialscan_role_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_role_arn)
	@echo -e $(bold)$(primary)trivialscan_policy_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_policy_arn)

build: ## makes the lambda zip archive
	./.$(BUILD_ENV)/bin/build-archive

build-prod: ## makes the lambda zip archive for prod
	APP_ENV=Prod ./.$(BUILD_ENV)/bin/build-archive

tfinstall:
	curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
	sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"
	sudo apt-get update
	sudo apt-get install -y terraform
	terraform -chdir=plans -install-autocomplete || true

init: ## Runs tf init tf
	terraform -chdir=plans init -reconfigure -upgrade=true

plan: ## Runs tf validate and tf plan
	terraform -chdir=plans validate
	terraform -chdir=plans plan -no-color -out=.tfplan
	terraform -chdir=plans show --json .tfplan | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfplan.json

apply: ## tf apply -auto-approve -refresh=true
	terraform -chdir=plans apply -auto-approve -refresh=true .tfplan

destroy: init ## tf destroy -auto-approve
	terraform -chdir=plans validate
	terraform -chdir=plans plan -destroy -no-color -out=.tfdestroy
	terraform -chdir=plans show --json .tfdestroy | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfdestroy.json
	terraform -chdir=plans apply -auto-approve -destroy .tfdestroy

test-local: ## Prettier test outputs
	pre-commit run --all-files
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

unit-test: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

docker-local: ## run the Lambda locally from the Docker container used to build the Terraform package
	docker run --rm -p 8080:8080 --name trivialscan-dashboard pip-builder:latest

run-local: ## A local server interfacing with Lambda URL
	(cd src; uvicorn app:app --reload --host 0.0.0.0)

lambda-local: ## Invoke the regular Lambda, not as the LambdaURL context
	curl -XPOST "http://localhost:8080/2015-03-31/functions/function/invocations" -d '{}'
