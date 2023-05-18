# build

## Simple building without automation and packaging

* Use the build.sh script in the ../scripts directory.

## Building images and pushing to image repositories, without automation

* Use the Makefile in the ../deployment directory.

## Packaging and Continuous Integration.

* Put your cloud (AMI), container (Docker), OS (deb, rpm, pkg) package configurations and scripts in the /build/package directory.

* Put your CI (travis, circle, drone) configurations and scripts in the /build/ci directory. 


