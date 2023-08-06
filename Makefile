.PHONY: default inventory bootstrap

host := $(shell terraform output -json instance_public_dns | jq -r '.[]')

default:
	@echo $(host)
	
inventory:
	@yq -i ".bsd.hosts = \"$(host)\"" inventory.yaml

bootstrap:
	@ssh $(host) 'su - root -c "pkg update && pkg install -y python3"'
