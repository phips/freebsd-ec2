# FreeBSD 14.2 ec2 bootstrap

Brings up FreeBSD 14.2 ARM instance on ec2. Defaults to t4g.micro (see [tfvars](terraform.tfvars)).

## Requirements

If running from a Mac, just '[brew](https://brew.sh) install' these:

- [terraform](https://developer.hashicorp.com/terraform/cli)
- [ansible](https://docs.ansible.com/ansible/latest/index.html)
- [jq](https://jqlang.github.io/jq/)
- [yq](https://mikefarah.gitbook.io/yq/)

## Running

```
$ terraform apply
$ make inventory
$ ./r
```

## Ansible play

Does a bit of cleaning up, installs some packages. See [inventory.yaml](inventory.yaml) and tune to your liking. There are a couple of tags for shortening the play if you're just making repeat changes to, say, packages after initial deploy.

```
$ ./r -t pkgs
```

## In use

Connecting to the running instance:

`ssh $(make)`

