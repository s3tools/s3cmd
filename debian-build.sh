#!/bin/bash

set -e

export DEBEMAIL="Michal Ludvig <mludvig@logix.net.nz>"
export SIGNKEY="S3tools <s3tools@s3tools.org>"
export DISTRIB="stable" # Either stable or testing

VERSION=$(./s3cmd --version | awk '{print $NF}')
echo -e "Building \033[32ms3cmd \033[31m${VERSION}\033[0m for Debian..."

rm -rf debian-build
mkdir -p debian-build
cd debian-build
cp ../dist/s3cmd-${VERSION}.tar.gz s3cmd_${VERSION}.orig.tar.gz
tar xf s3cmd_${VERSION}.orig.tar.gz
svn export ../debian s3cmd-${VERSION}/debian
cd s3cmd-${VERSION}
debchange -D${DISTRIB} -d
cp debian/changelog ../../debian/
debuild -m"${SIGNKEY}"
cd ..
echo -e "\033[1;32m=== Build: Success ===\033[0m"

rm -f s3cmd_${VERSION}*.build
mkdir -p repository/${DISTRIB}
mv s3cmd_* repository/${DISTRIB}
gpg --export -a "${SIGNKEY}" > repository/${DISTRIB}/s3tools.key

cd repository/
cp -a ../s3cmd-${VERSION}/debian/mini-dinstall* .
PATH_OLD=${PATH}
export PATH=${PATH}:$(pwd)
mini-dinstall --batch --config=mini-dinstall.conf -v
export PATH=${OLD_PATH}
echo -e "\033[1;32m=== Repo: Success ===\033[0m"
echo
echo -e "You can now upload \033[1mdebian-build/repository/${DISTRIB}\033[0m to the Internet"
