#!/bin/sh

VERSION=$(./s3cmd --version | awk '{print $NF}')
echo -e "Uploading \033[32ms3cmd \033[31m${VERSION}\033[0m ..."
rsync -avP dist/s3cmd-${VERSION}.* ludvigm@frs.sourceforge.net:uploads/
