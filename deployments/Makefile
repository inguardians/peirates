build:
	test $(IMG_REPO)
	docker-compose build peirates
	@echo "Size of image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}') $(IMG_REPO):latest

dev:
	docker-compose build peirates-dev
	test $(IMG_REPO_DEV)
	@echo "Size of image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}') $IMG_REPO_DEV}:latest

.check-env-vars:
	@test $${CR_PAT?Push will fail. You need to export the CR_PAT token for GHCR}

push: .check-env-vars
	test $(IMG_REPO)
	docker push $(IMG_REPO):latest

push-dev: .check-env-vars
	test $(IMG_REPO_DEV)
	docker push $(IMG_REPO_DEV):latest
