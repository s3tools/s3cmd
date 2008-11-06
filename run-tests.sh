#!/bin/sh
set -e -x

TEST_BUCKET="s3://s3cmd-autotest-$(id -un)-$(date +%s)"
echo "Using test bucket: ${TEST_BUCKET}"
echo
sleep 1

./s3cmd mb ${TEST_BUCKET}
./s3cmd ls ${TEST_BUCKET}
./s3cmd put s3cmd s3cmd.1 ${TEST_BUCKET}
./s3cmd ls ${TEST_BUCKET}
./s3cmd del ${TEST_BUCKET}/s3cmd.1
./s3cmd get ${TEST_BUCKET}/s3cmd s3cmd.get
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
./s3cmd sync s3cmd-${VER} ${TEST_BUCKET}/sync-test
echo "Added file" > s3cmd-${VER}/added.file
rm -f s3cmd-${VER}/file.to.remove
./s3cmd sync --delete s3cmd-${VER} ${TEST_BUCKET}/sync-test
rm -f s3cmd-${VER}/S3/PkgInfo.py
rm -f s3cmd-${VER}/s3cmd
./s3cmd sync --delete --exclude "/s3cmd-${VER}/S3/*" ${TEST_BUCKET}/sync-test s3cmd-${VER}
rm -rf s3cmd-${VER}

./s3cmd rb ${TEST_BUCKET}/ || true
# ERROR: S3 error: 409 (Conflict): BucketNotEmpty

# hack to remove all objects from a bucket
mkdir empty
./s3cmd sync --delete empty/ ${TEST_BUCKET}
rm -rf empty

./s3cmd rb ${TEST_BUCKET}/

set +x

echo; echo
echo; echo
echo "=== All good. Ready for release :-) ==="
echo
