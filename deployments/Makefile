help:
	@echo "This Makefile can create and push container images."
	@echo 'To use the build and push Makefile targets, you must set the $IMG_REPO environment variable'
	@echo 'To use the build-dev and push-dev Makefile targets, you must set the $IMG_REPO_DEV environment variable'

binary:
	docker-compose build peirates-static

build:
	@echo "building image and tagging with repo $(IMG_REPO) - this tag is stored in environment variable IMG_REPO"
	test $(IMG_REPO)
	docker-compose build peirates
	@echo "Size of image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates | grep -v dev | awk -F '  +' '{print $$3}') $(IMG_REPO):latest

build-dev:  dev

dev:
	@echo "building image and tagging with repo $(IMG_REPO_DEV) - this tag is stored in environment varialbe IMG_REPO_DEV"
	test $(IMG_REPO_DEV)
	docker-compose build peirates-dev
	@echo "Size of image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$5}')"
	@echo "Tagging image: $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}')"
	docker tag $(shell docker image ls| grep ^peirates-dev | awk -F '  +' '{print $$3}') $(IMG_REPO_DEV):latest

.check-env-vars:
	@test $${CR_PAT?Push will fail. You need to export the CR_PAT token for GHCR}

push: .check-env-vars
	test $(IMG_REPO)
	docker push $(IMG_REPO):latest

push-dev: .check-env-vars
	test $(IMG_REPO_DEV)
	docker push $(IMG_REPO_DEV):latest
