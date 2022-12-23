.check-env-vars:
	@test $${CR_PAT?Push will fail. You need to export the CR_PAT token for GHCR}

build:
	docker-compose build peirates
	@echo "Size of image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}') ghcr.io/devsecfranklin/peirates:latest

dev:
	docker-compose build peirates-dev
	@echo "Size of image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}') ghcr.io/devsecfranklin/peirates-dev:latest

push:
	docker push ghcr.io/devsecfranklin/peirates:latest

push-dev:
	docker push ghcr.io/devsecfranklin/peirates-dev:latest