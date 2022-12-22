.check-env-vars:
	@test $${CR_PAT?Push will fail. You need to export the CR_PAT token for GHCR}

build:
	docker-compose build peirates
	@echo "Size of image: $(shell docker image ls | head -2 | grep ^peirates | rev | cut -d' ' -f1 | rev)"
	@echo "Tagging image:  $(shell docker images -q | head -1)"
	docker tag $(shell docker images -q | head -1) ghcr.io/devsecfranklin/peirates:latest

dev:
	docker-compose build peirates-dev
	@echo "Size of image: $(shell docker image ls | head -2 | grep peirates | rev | cut -d' ' -f1 | rev)"
	@echo "Tagging image:  $(shell docker images -q | head -1)"
	docker tag $(shell docker images -q | head -1) ghcr.io/devsecfranklin/peirates-dev:latest

push:
	docker push ghcr.io/devsecfranklin/peirates:latest

push-dev:
	docker push ghcr.io/devsecfranklin/peirates-dev:latest