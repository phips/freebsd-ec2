.PHONY: default inventory

host := $(shell terraform output -json instance_public_dns | jq -r '.[]')

default:
	@echo $(host)
	
inventory:
	@yq -i ".bsd.hosts = \"$(host)\"" inventory.yaml

