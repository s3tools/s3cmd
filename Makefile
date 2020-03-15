SHELL  := /bin/bash
VERSION := $(shell /usr/bin/env python2 -c 'from S3 import PkgInfo;print PkgInfo.version')
SPEC   := s3cmd.spec
COMMIT := $(shell git rev-parse HEAD)
SHORTCOMMIT := $(shell git rev-parse --short=8 HEAD)
TARBALL = s3cmd-$(VERSION)-$(SHORTCOMMIT).tar.gz

release:
	python2 setup.py register sdist upload --sign

clean:
	-rm -rf s3cmd-*.tar.gz *.rpm *~ $(SPEC)
	-find . -name \*.pyc -exec rm \{\} \;
	-find . -name \*.pyo -exec rm \{\} \;

$(SPEC): $(SPEC).in
	sed -e 's/##VERSION##/$(VERSION)/' \
            -e 's/##COMMIT##/$(COMMIT)/' \
            -e 's/##SHORTCOMMIT##/$(SHORTCOMMIT)/' \
            $(SPEC).in > $(SPEC)

# fixme: python setup.py sdist also generates a PKG-INFO file which we don't have using straight git archive
git-tarball:
	git archive --format tar --prefix s3cmd-$(COMMIT)/ HEAD S3/ s3cmd NEWS README.md LICENSE INSTALL.md setup.cfg s3cmd.1 setup.py| gzip -c > $(TARBALL)

# Use older digest algorithms for local rpmbuilds, as EPEL5 and
# earlier releases need this.  When building using mock for a
# particular target, it will use the proper (newer) digests if that
# target supports it.
git-rpm: clean git-tarball $(SPEC)
	tmp_dir=`mktemp -d` ; \
	mkdir -p $${tmp_dir}/{BUILD,RPMS,SRPMS,SPECS,SOURCES} ; \
	cp $(TARBALL) $${tmp_dir}/SOURCES ; \
	cp $(SPEC) $${tmp_dir}/SPECS ; \
	cd $${tmp_dir} > /dev/null 2>&1; \
	rpmbuild -ba --define "_topdir $${tmp_dir}" \
	  --define "_source_filedigest_algorithm 0" \
	  --define "_binary_filedigest_algorithm 0" \
	  --define "dist %{nil}" \
          SPECS/$(SPEC) ; \
	cd - > /dev/null 2>&1; \
	cp $${tmp_dir}/RPMS/noarch/* $${tmp_dir}/SRPMS/* . ; \
	rm -rf $${tmp_dir} ; \
	rpmlint *.rpm *.spec
