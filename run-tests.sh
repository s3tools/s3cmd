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

echo; echo 
echo "=== Now running 'sync' tests ==="
echo; echo 

VER=$(./s3cmd --version | cut -d\  -f3)
tar xvfz dist/s3cmd-${VER}.tar.gz
echo "Will be removed" > s3cmd-${VER}/file.to.remove
./s3cmd sync s3cmd-${VER} s3://s3cmd-autotest/sync-test
echo "Added file" > s3cmd-${VER}/added.file
rm -f s3cmd-${VER}/file.to.remove
./s3cmd sync --delete s3cmd-${VER} s3://s3cmd-autotest/sync-test
rm -rf s3cmd-${VER}

./s3cmd rb s3://s3cmd-autotest/ || true
# ERROR: S3 error: 409 (Conflict): BucketNotEmpty

# hack to remove all objects from a bucket
mkdir empty
./s3cmd sync --delete empty/ s3://s3cmd-autotest
rm -rf empty

./s3cmd rb s3://s3cmd-autotest/

echo; echo
echo; echo
echo "=== All good. Ready for release :-) ==="
echo
