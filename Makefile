NAME			= s3cmd
VERSION			= 1.5.0
RELEASE			= alpha3
ARCH			= noarch

RPM_TOPDIR ?= $(shell rpm --eval '%{_topdir}')

SHELL := /bin/bash
RPMBUILD_ARGS := \
	--define "name $(NAME)" \
	--define "version $(VERSION)" \
	--define "release $(RELEASE)"

.PHONY: all release rpm 

all:
	@echo "Usage: make rpm|release"
	
release:
	python setup.py register sdist upload

rpm:
	mkdir -p $(RPM_TOPDIR)/SOURCES
	mkdir -p $(RPM_TOPDIR)/SPECS
	mkdir -p $(RPM_TOPDIR)/BUILD
	mkdir -p $(RPM_TOPDIR)/RPMS/$(ARCH)
	mkdir -p $(RPM_TOPDIR)/SRPMS
	rm -Rf $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION)
	cp -r . $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION)
	tar czf $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION).tar.gz -C $(RPM_TOPDIR)/SOURCES --exclude ".git" $(NAME)-$(VERSION)
	rm -Rf $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION)
	cp $(NAME).spec $(RPM_TOPDIR)/SPECS/
	rpmbuild $(RPMBUILD_ARGS) -ba --clean $(NAME).spec