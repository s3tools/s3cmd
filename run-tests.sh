#!/bin/sh
set -e -x

./s3cmd mb s3://s3cmd-autotest
./s3cmd ls s3://s3cmd-autotest
./s3cmd put s3cmd s3cmd.1 s3://s3cmd-autotest
./s3cmd ls s3://s3cmd-autotest
./s3cmd del s3://s3cmd-autotest/s3cmd.1
./s3cmd get s3://s3cmd-autotest/s3cmd s3cmd.get
diff s3cmd s3cmd.get
rm -fv s3cmd.get

set +x
echo; echo 
echo "=== Now running 'sync' tests ==="
echo; echo 
set -x

VER=$(./s3cmd --version | cut -d\  -f3)
tar xvfz dist/s3cmd-${VER}.tar.gz
echo "Will be removed" > s3cmd-${VER}/file.to.remove
./s3cmd sync s3cmd-${VER} s3://s3cmd-autotest/sync-test
echo "Added file" > s3cmd-${VER}/added.file
rm -f s3cmd-${VER}/file.to.remove
./s3cmd sync --delete s3cmd-${VER} s3://s3cmd-autotest/sync-test
rm -f s3cmd-${VER}/S3/PkgInfo.py
rm -f s3cmd-${VER}/s3cmd
./s3cmd sync --delete --exclude "/s3cmd-${VER}/S3/S3*" s3://s3cmd-autotest/sync-test s3cmd-${VER}
rm -rf s3cmd-${VER}

./s3cmd rb s3://s3cmd-autotest/ || true
# ERROR: S3 error: 409 (Conflict): BucketNotEmpty

./s3cmd rb --force s3://s3cmd-autotest/

set +x

echo; echo
echo; echo
echo "=== All good. Ready for release :-) ==="
echo
