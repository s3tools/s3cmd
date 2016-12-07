#!/usr/bin/env python2
# -*- coding=utf-8 -*-

## Amazon S3cmd - testsuite
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import absolute_import, print_function

import sys
import os
import re
import time
from subprocess import Popen, PIPE, STDOUT
import locale
import getpass
import S3.Exceptions
import S3.Config
from S3.ExitCodes import *

count_pass = 0
count_fail = 0
count_skip = 0

test_counter = 0
run_tests = []
exclude_tests = []

verbose = False

# https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python/377028#377028
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

if which('curl') is not None:
    have_curl = True
else:
    have_curl = False

config_file = None
if os.getenv("HOME"):
    config_file = os.path.join(os.getenv("HOME"), ".s3cfg")
elif os.name == "nt" and os.getenv("USERPROFILE"):
    config_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), os.getenv("APPDATA").decode('mbcs') or 'Application Data', "s3cmd.ini")


## Unpack testsuite/ directory
if not os.path.isdir('testsuite') and os.path.isfile('testsuite.tar.gz'):
    os.system("tar -xz -f testsuite.tar.gz")
if not os.path.isdir('testsuite'):
    print("Something went wrong while unpacking testsuite.tar.gz")
    sys.exit(1)

os.system("tar -xf testsuite/checksum.tar -C testsuite")
if not os.path.isfile('testsuite/checksum/cksum33.txt'):
    print("Something went wrong while unpacking testsuite/checkum.tar")
    sys.exit(1)

## Fix up permissions for permission-denied tests
os.chmod("testsuite/permission-tests/permission-denied-dir", 0o444)
os.chmod("testsuite/permission-tests/permission-denied.txt", 0o000)

## Patterns for Unicode tests
patterns = {}
patterns['UTF-8'] = u"ŪņЇЌœđЗ/☺ unicode € rocks ™"
patterns['GBK'] = u"12月31日/1-特色條目"

encoding = locale.getpreferredencoding()
if not encoding:
    print("Guessing current system encoding failed. Consider setting $LANG variable.")
    sys.exit(1)
else:
    print("System encoding: " + encoding)

have_encoding = os.path.isdir('testsuite/encodings/' + encoding)
if not have_encoding and os.path.isfile('testsuite/encodings/%s.tar.gz' % encoding):
    os.system("tar xvz -C testsuite/encodings -f testsuite/encodings/%s.tar.gz" % encoding)
    have_encoding = os.path.isdir('testsuite/encodings/' + encoding)

if have_encoding:
    #enc_base_remote = "%s/xyz/%s/" % (pbucket(1), encoding)
    enc_pattern = patterns[encoding]
else:
    print(encoding + " specific files not found.")
# Minio: disable encoding tests
have_encoding = False

if not os.path.isdir('testsuite/crappy-file-name'):
    os.system("tar xvz -C testsuite -f testsuite/crappy-file-name.tar.gz")
    # TODO: also unpack if the tarball is newer than the directory timestamp
    #       for instance when a new version was pulled from SVN.

def test(label, cmd_args = [], retcode = 0, must_find = [], must_not_find = [], must_find_re = [], must_not_find_re = [], stdin = None):
    def command_output():
        print("----")
        print(" ".join([" " in arg and "'%s'" % arg or arg for arg in cmd_args]))
        print("----")
        print(stdout)
        print("----")

    def failure(message = ""):
        global count_fail
        if message:
            message = u"  (%r)" % message
        print(u"\x1b[31;1mFAIL%s\x1b[0m" % (message))
        count_fail += 1
        command_output()
        #return 1
        sys.exit(1)
    def success(message = ""):
        global count_pass
        if message:
            message = "  (%r)" % message
        print("\x1b[32;1mOK\x1b[0m%s" % (message))
        count_pass += 1
        if verbose:
            command_output()
        return 0
    def skip(message = ""):
        global count_skip
        if message:
            message = "  (%r)" % message
        print("\x1b[33;1mSKIP\x1b[0m%s" % (message))
        count_skip += 1
        return 0
    def compile_list(_list, regexps = False):
        if regexps == False:
            _list = [re.escape(item.encode(encoding, "replace")) for item in _list]

        return [re.compile(item, re.MULTILINE) for item in _list]

    global test_counter
    test_counter += 1
    print(("%3d  %s " % (test_counter, label)).ljust(30, "."), end=' ')
    sys.stdout.flush()

    if run_tests.count(test_counter) == 0 or exclude_tests.count(test_counter) > 0:
        return skip()

    if not cmd_args:
        return skip()

    p = Popen(cmd_args, stdin = stdin, stdout = PIPE, stderr = STDOUT, universal_newlines = True, close_fds = True)
    stdout, stderr = p.communicate()
    if type(retcode) not in [list, tuple]: retcode = [retcode]
    if p.returncode not in retcode:
        return failure("retcode: %d, expected one of: %s" % (p.returncode, retcode))

    if type(must_find) not in [ list, tuple ]: must_find = [must_find]
    if type(must_find_re) not in [ list, tuple ]: must_find_re = [must_find_re]
    if type(must_not_find) not in [ list, tuple ]: must_not_find = [must_not_find]
    if type(must_not_find_re) not in [ list, tuple ]: must_not_find_re = [must_not_find_re]

    find_list = []
    find_list.extend(compile_list(must_find))
    find_list.extend(compile_list(must_find_re, regexps = True))
    find_list_patterns = []
    find_list_patterns.extend(must_find)
    find_list_patterns.extend(must_find_re)

    not_find_list = []
    not_find_list.extend(compile_list(must_not_find))
    not_find_list.extend(compile_list(must_not_find_re, regexps = True))
    not_find_list_patterns = []
    not_find_list_patterns.extend(must_not_find)
    not_find_list_patterns.extend(must_not_find_re)

    for index in range(len(find_list)):
        match = find_list[index].search(stdout)
        if not match:
            return failure("pattern not found: %s" % find_list_patterns[index])
    for index in range(len(not_find_list)):
        match = not_find_list[index].search(stdout)
        if match:
            return failure("pattern found: %s (match: %s)" % (not_find_list_patterns[index], match.group(0)))

    return success()

def test_s3cmd(label, cmd_args = [], **kwargs):
    if not cmd_args[0].endswith("s3cmd"):
        cmd_args.insert(0, "python")
        cmd_args.insert(1, "s3cmd")
        if config_file:
            cmd_args.insert(2, "-c")
            cmd_args.insert(3, config_file)

    return test(label, cmd_args, **kwargs)

def test_mkdir(label, dir_name):
    if os.name in ("posix", "nt"):
        cmd = ['mkdir', '-p']
    else:
        print("Unknown platform: %s" % os.name)
        sys.exit(1)
    cmd.append(dir_name)
    return test(label, cmd)

def test_rmdir(label, dir_name):
    if os.path.isdir(dir_name):
        if os.name == "posix":
            cmd = ['rm', '-rf']
        elif os.name == "nt":
            cmd = ['rmdir', '/s/q']
        else:
            print("Unknown platform: %s" % os.name)
            sys.exit(1)
        cmd.append(dir_name)
        return test(label, cmd)
    else:
        return test(label, [])

def test_flushdir(label, dir_name):
    test_rmdir(label + "(rm)", dir_name)
    return test_mkdir(label + "(mk)", dir_name)

def test_copy(label, src_file, dst_file):
    if os.name == "posix":
        cmd = ['cp', '-f']
    elif os.name == "nt":
        cmd = ['copy']
    else:
        print("Unknown platform: %s" % os.name)
        sys.exit(1)
    cmd.append(src_file)
    cmd.append(dst_file)
    return test(label, cmd)

def test_curl_HEAD(label, src_file, **kwargs):
    cmd = ['curl', '--silent', '--head', '-include', '--location']
    cmd.append(src_file)
    return test(label, cmd, **kwargs)

bucket_prefix = u"%s-" % getpass.getuser()

argv = sys.argv[1:]
while argv:
    arg = argv.pop(0)
    if arg.startswith('--bucket-prefix='):
        print("Usage: '--bucket-prefix PREFIX', not '--bucket-prefix=PREFIX'")
        sys.exit(0)
    if arg in ("-h", "--help"):
        print("%s A B K..O -N" % sys.argv[0])
        print("Run tests number A, B and K through to O, except for N")
        sys.exit(0)

    if arg in ("-c", "--config"):
        config_file = argv.pop(0)
        continue
    if arg in ("-l", "--list"):
        exclude_tests = range(0, 999)
        break
    if arg in ("-v", "--verbose"):
        verbose = True
        continue
    if arg in ("-p", "--bucket-prefix"):
        try:
            bucket_prefix = argv.pop(0)
        except IndexError:
            print("Bucket prefix option must explicitly supply a bucket name prefix")
            sys.exit(0)
        continue
    if ".." in arg:
        range_idx = arg.find("..")
        range_start = arg[:range_idx] or 0
        range_end = arg[range_idx+2:] or 999
        run_tests.extend(range(int(range_start), int(range_end) + 1))
    elif arg.startswith("-"):
        exclude_tests.append(int(arg[1:]))
    else:
        run_tests.append(int(arg))

print("Using bucket prefix: '%s'" % bucket_prefix)

cfg = S3.Config.Config(config_file)

if not run_tests:
    run_tests = range(0, 999)

# helper functions for generating bucket names
def bucket(tail):
        '''Test bucket name'''
        label = 'autotest'
        if str(tail) == '3':
                label = 'autotest'
        return '%ss3cmd-%s-%s' % (bucket_prefix, label, tail)

def pbucket(tail):
        '''Like bucket(), but prepends "s3://" for you'''
        return 's3://' + bucket(tail)

## ====== Remove test buckets
test_s3cmd("Remove test buckets", ['rb', '-r', '--force', pbucket(1), pbucket(2), pbucket(3)])

## ====== verify they were removed
test_s3cmd("Verify no test buckets", ['ls'],
           must_not_find = [pbucket(1), pbucket(2), pbucket(3)])


## ====== Create one bucket (EU)
# Disabled for minio
#test_s3cmd("Create one bucket (EU)", ['mb', '--bucket-location=EU', pbucket(1)],
#    must_find = "Bucket '%s/' created" % pbucket(1))
test_s3cmd("Create one bucket", ['mb', pbucket(1)],
    must_find = "Bucket '%s/' created" % pbucket(1))


## ====== Create multiple buckets
test_s3cmd("Create multiple buckets", ['mb', pbucket(2), pbucket(3)],
    must_find = [ "Bucket '%s/' created" % pbucket(2), "Bucket '%s/' created" % pbucket(3)])


## ====== Invalid bucket name
test_s3cmd("Invalid bucket name", ["mb", "--bucket-location=EU", pbucket('EU')],
    retcode = EX_USAGE,
    must_find = "ERROR: Parameter problem: Bucket name '%s' contains disallowed character" % bucket('EU'),
    must_not_find_re = "Bucket.*created")


## ====== Buckets list
# Modified for Minio
test_s3cmd("Buckets list", ["ls"],
    must_find = [ "autotest-1", "autotest-2", "autotest-3" ], must_not_find_re = "autotest-EU")


## ====== Sync to S3
# Modified for Minio (exclude crappy dir)
test_s3cmd("Sync to S3", ['sync', 'testsuite/', pbucket(1) + '/xyz/', '--exclude', 'demo/*', '--exclude', '*.png', '--no-encrypt', '--exclude-from', 'testsuite/exclude.encodings', '--exclude', 'crappy-file-name/*' ],
           must_find = [ "ERROR: Upload of 'testsuite/permission-tests/permission-denied.txt' is not possible (Reason: Permission denied)",
           ],
           must_not_find_re = [ "demo/", "^(?!WARNING: Skipping).*\.png$", "permission-denied-dir" ],
           retcode = EX_PARTIAL)

if have_encoding:
    ## ====== Sync UTF-8 / GBK / ... to S3
    test_s3cmd(u"Sync %s to S3" % encoding, ['sync', 'testsuite/encodings/' + encoding, '%s/xyz/encodings/' % pbucket(1), '--exclude', 'demo/*', '--no-encrypt' ],
        must_find = [ u"'testsuite/encodings/%(encoding)s/%(pattern)s' -> '%(pbucket)s/xyz/encodings/%(encoding)s/%(pattern)s'" % { 'encoding' : encoding, 'pattern' : enc_pattern , 'pbucket' : pbucket(1)} ])


## ====== List bucket content
test_s3cmd("List bucket content", ['ls', '%s/xyz/' % pbucket(1) ],
    must_find_re = [ u"DIR +%s/xyz/binary/$" % pbucket(1) , u"DIR +%s/xyz/etc/$" % pbucket(1) ],
    must_not_find = [ u"random-crap.md5", u"/demo" ])


## ====== List bucket recursive
must_find = [ u"%s/xyz/binary/random-crap.md5" % pbucket(1) ]
if have_encoding:
    must_find.append(u"%(pbucket)s/xyz/encodings/%(encoding)s/%(pattern)s" % { 'encoding' : encoding, 'pattern' : enc_pattern, 'pbucket' : pbucket(1) })

test_s3cmd("List bucket recursive", ['ls', '--recursive', pbucket(1)],
    must_find = must_find,
    must_not_find = [ "logo.png" ])

## ====== FIXME
# test_s3cmd("Recursive put", ['put', '--recursive', 'testsuite/etc', '%s/xyz/' % pbucket(1) ])


## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")

## ====== Put from stdin
f = open('testsuite/single-file/single-file.txt', 'r')
test_s3cmd("Put from stdin", ['put', '-', '%s/single-file/single-file.txt' % pbucket(1)],
           must_find = ["'<stdin>' -> '%s/single-file/single-file.txt'" % pbucket(1)],
           stdin = f)
f.close()

## ====== Multipart put
os.system('dd if=/dev/urandom of=testsuite-out/urandom.bin bs=1M count=16 > /dev/null 2>&1')
test_s3cmd("Put multipart", ['put', '--multipart-chunk-size-mb=5', 'testsuite-out/urandom.bin', '%s/urandom.bin' % pbucket(1)],
           must_not_find = ['abortmp'])

## ====== Multipart put from stdin
f = open('testsuite-out/urandom.bin', 'r')
test_s3cmd("Multipart large put from stdin", ['put', '--multipart-chunk-size-mb=5', '-', '%s/urandom2.bin' % pbucket(1)],
           must_find = ['%s/urandom2.bin' % pbucket(1)],
           must_not_find = ['abortmp'],
           stdin = f)
f.close()

## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")

## ====== Sync from S3
must_find = [ "'%s/xyz/binary/random-crap.md5' -> 'testsuite-out/xyz/binary/random-crap.md5'" % pbucket(1) ]
if have_encoding:
    must_find.append(u"'%(pbucket)s/xyz/encodings/%(encoding)s/%(pattern)s' -> 'testsuite-out/xyz/encodings/%(encoding)s/%(pattern)s' " % { 'encoding' : encoding, 'pattern' : enc_pattern, 'pbucket' : pbucket(1) })
test_s3cmd("Sync from S3", ['sync', '%s/xyz' % pbucket(1), 'testsuite-out'],
    must_find = must_find)


## ====== Remove 'demo' directory
test_rmdir("Remove 'dir-test/'", "testsuite-out/xyz/dir-test/")


## ====== Create dir with name of a file
test_mkdir("Create file-dir dir", "testsuite-out/xyz/dir-test/file-dir")


## ====== Skip dst dirs
test_s3cmd("Skip over dir", ['sync', '%s/xyz' % pbucket(1), 'testsuite-out'],
           must_find = "ERROR: Download of 'xyz/dir-test/file-dir' failed (Reason: testsuite-out/xyz/dir-test/file-dir is a directory)",
           retcode = EX_PARTIAL)


## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")


## ====== Put public, guess MIME
test_s3cmd("Put public, guess MIME", ['put', '--guess-mime-type', '--acl-public', 'testsuite/etc/logo.png', '%s/xyz/etc/logo.png' % pbucket(1)],
    must_find = [ "-> '%s/xyz/etc/logo.png'" % pbucket(1) ])


## ====== Retrieve from URL
# Minio: disabled
#if have_curl:
#   test_curl_HEAD("Retrieve from URL", 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base),
#                   must_find_re = ['Content-Length: 22059'])

## ====== Change ACL to Private
# Minio: disabled
#test_s3cmd("Change ACL to Private", ['setacl', '--acl-private', '%s/xyz/etc/l*.png' % pbucket(1)],
#    must_find = [ "logo.png: ACL set to Private" ])


## ====== Verify Private ACL
# Minio: disabled
#if have_curl:
#    test_curl_HEAD("Verify Private ACL", 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base),
#                   must_find_re = [ '403 Forbidden' ])


## ====== Change ACL to Public
# Minio: disabled
#test_s3cmd("Change ACL to Public", ['setacl', '--acl-public', '--recursive', '%s/xyz/etc/' % pbucket(1) , '-v'],
#    must_find = [ "logo.png: ACL set to Public" ])


## ====== Verify Public ACL
# Minio: disabled
#if have_curl:
#    test_curl_HEAD("Verify Public ACL", 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base),
#                   must_find_re = [ '200 OK',
#                                    'Content-Length: 22059'])


## ====== Sync more to S3
# Modified for Minio (exclude crappy dir)
test_s3cmd("Sync more to S3", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--exclude', 'crappy-file-name/*' ],
           must_find = [ "'testsuite/demo/some-file.xml' -> '%s/xyz/demo/some-file.xml' " % pbucket(1) ],
           must_not_find = [ "'testsuite/etc/linked.png' -> '%s/xyz/etc/linked.png'" % pbucket(1) ],
           retcode = EX_PARTIAL)


## ====== Don't check MD5 sum on Sync
test_copy("Change file cksum1.txt", "testsuite/checksum/cksum2.txt", "testsuite/checksum/cksum1.txt")
test_copy("Change file cksum33.txt", "testsuite/checksum/cksum2.txt", "testsuite/checksum/cksum33.txt")
# Modified for Minio (exclude crappy dir)
test_s3cmd("Don't check MD5", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--no-check-md5', '--exclude', 'crappy-file-name/*'],
           must_find = [ "cksum33.txt" ],
           must_not_find = [ "cksum1.txt" ],
           retcode = EX_PARTIAL)


## ====== Check MD5 sum on Sync
# Modified for Minio (exclude crappy dir)
test_s3cmd("Check MD5", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--check-md5', '--exclude', 'crappy-file-name/*'],
           must_find = [ "cksum1.txt" ],
           retcode = EX_PARTIAL)


## ====== Rename within S3
test_s3cmd("Rename within S3", ['mv', '%s/xyz/etc/logo.png' % pbucket(1), '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    must_find = [ "move: '%s/xyz/etc/logo.png' -> '%s/xyz/etc2/Logo.PNG'" % (pbucket(1), pbucket(1))])


## ====== Rename (NoSuchKey)
test_s3cmd("Rename (NoSuchKey)", ['mv', '%s/xyz/etc/logo.png' % pbucket(1), '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    retcode = EX_NOTFOUND,
    must_find_re = [ 'Key not found' ],
    must_not_find = [ "move: '%s/xyz/etc/logo.png' -> '%s/xyz/etc2/Logo.PNG'" % (pbucket(1), pbucket(1)) ])

## ====== Sync more from S3 (invalid src)
test_s3cmd("Sync more from S3 (invalid src)", ['sync', '--delete-removed', '%s/xyz/DOESNOTEXIST' % pbucket(1), 'testsuite-out'],
    must_not_find = [ "delete: 'testsuite-out/logo.png'" ])

## ====== Sync more from S3
test_s3cmd("Sync more from S3", ['sync', '--delete-removed', '%s/xyz' % pbucket(1), 'testsuite-out'],
    must_find = [ "'%s/xyz/etc2/Logo.PNG' -> 'testsuite-out/xyz/etc2/Logo.PNG'" % pbucket(1),
                  "'%s/xyz/demo/some-file.xml' -> 'testsuite-out/xyz/demo/some-file.xml'" % pbucket(1) ],
    must_not_find_re = [ "not-deleted.*etc/logo.png", "delete: 'testsuite-out/logo.png'" ])


## ====== Make dst dir for get
test_rmdir("Remove dst dir for get", "testsuite-out")


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc/AtomicClockRadio.ttf' % pbucket(1), 'testsuite-out'],
    retcode = EX_USAGE,
    must_find = [ 'Destination must be a directory or stdout when downloading multiple sources.' ])

## ====== put/get non-ASCII filenames
test_s3cmd("Put unicode filenames", ['put', u'testsuite/encodings/UTF-8/ŪņЇЌœđЗ/Žůžo',  u'%s/xyz/encodings/UTF-8/ŪņЇЌœđЗ/Žůžo' % pbucket(1)],
           retcode = 0,
           must_find = [ '->' ])


## ====== Make dst dir for get
test_mkdir("Make dst dir for get", "testsuite-out")


## ====== put/get non-ASCII filenames
test_s3cmd("Get unicode filenames", ['get', u'%s/xyz/encodings/UTF-8/ŪņЇЌœđЗ/Žůžo' % pbucket(1), 'testsuite-out'],
           retcode = 0,
           must_find = [ '->' ])


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc/AtomicClockRadio.ttf' % pbucket(1), 'testsuite-out'],
    must_find = [ u"-> 'testsuite-out/Logo.PNG'",
                  u"-> 'testsuite-out/AtomicClockRadio.ttf'" ])

## ====== Upload files differing in capitalisation
test_s3cmd("blah.txt / Blah.txt", ['put', '-r', 'testsuite/blahBlah', pbucket(1)],
    must_find = [ '%s/blahBlah/Blah.txt' % pbucket(1), '%s/blahBlah/blah.txt' % pbucket(1)])

## ====== Copy between buckets
test_s3cmd("Copy between buckets", ['cp', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc2/logo.png' % pbucket(3)],
    must_find = [ "remote copy: '%s/xyz/etc2/Logo.PNG' -> '%s/xyz/etc2/logo.png'" % (pbucket(1), pbucket(3)) ])

## ====== Recursive copy
test_s3cmd("Recursive copy, set ACL", ['cp', '-r', '--acl-public', '%s/xyz/' % pbucket(1), '%s/copy' % pbucket(2), '--exclude', 'demo/dir?/*.txt', '--exclude', 'non-printables*'],
    must_find = [ "remote copy: '%s/xyz/etc2/Logo.PNG' -> '%s/copy/etc2/Logo.PNG'" % (pbucket(1), pbucket(2)),
                  "remote copy: '%s/xyz/blahBlah/Blah.txt' -> '%s/copy/blahBlah/Blah.txt'" % (pbucket(1), pbucket(2)),
                  "remote copy: '%s/xyz/blahBlah/blah.txt' -> '%s/copy/blahBlah/blah.txt'" % (pbucket(1), pbucket(2)) ],
    must_not_find = [ "demo/dir1/file1-1.txt" ])

## ====== Verify ACL and MIME type
# Minio: disable acl check, not supported by minio
test_s3cmd("Verify ACL and MIME type", ['info', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
    must_find_re = [ "MIME type:.*image/png" ])

## ====== modify MIME type
# Minio: disable acl check, not supported by minio
# Minio: modifying mime type alone not allowed as copy of same file for them
#test_s3cmd("Modify MIME type", ['modify', '--mime-type=binary/octet-stream', '%s/copy/etc2/Logo.PNG' % pbucket(2) ])

#test_s3cmd("Verify ACL and MIME type", ['info', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
#    must_find_re = [ "MIME type:.*binary/octet-stream" ])

# Minio: disable acl check, not supported by minio
#test_s3cmd("Modify MIME type back", ['modify', '--mime-type=image/png', '%s/copy/etc2/Logo.PNG' % pbucket(2) ])

# Minio: disable acl check, not supported by minio
#test_s3cmd("Verify ACL and MIME type", ['info', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
#    must_find_re = [ "MIME type:.*image/png" ])

#test_s3cmd("Add cache-control header", ['modify', '--add-header=cache-control: max-age=3600, public', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
#    must_find_re = [ "modify: .*" ])

#if have_curl:
#    test_curl_HEAD("HEAD check Cache-Control present", 'http://%s.%s/copy/etc2/Logo.PNG' % (bucket(2), cfg.host_base),
#                   must_find_re = [ "Cache-Control: max-age=3600" ])

#test_s3cmd("Remove cache-control header", ['modify', '--remove-header=cache-control', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
#           must_find_re = [ "modify: .*" ])

#if have_curl:
#    test_curl_HEAD("HEAD check Cache-Control not present", 'http://%s.%s/copy/etc2/Logo.PNG' % (bucket(2), cfg.host_base),
#                   must_not_find_re = [ "Cache-Control: max-age=3600" ])

## ====== sign
test_s3cmd("sign string", ['sign', 's3cmd'], must_find_re = ["Signature:"])
test_s3cmd("signurl time", ['signurl', '%s/copy/etc2/Logo.PNG' % pbucket(2), str(int(time.time()) + 60)], must_find_re = ["http://"])
test_s3cmd("signurl time offset", ['signurl', '%s/copy/etc2/Logo.PNG' % pbucket(2), '+60'], must_find_re = ["https?://"])
test_s3cmd("signurl content disposition and type", ['signurl', '%s/copy/etc2/Logo.PNG' % pbucket(2), '+60', '--content-disposition=inline; filename=video.mp4', '--content-type=video/mp4'], must_find_re = [ 'response-content-disposition', 'response-content-type' ] )

## ====== Rename within S3
test_s3cmd("Rename within S3", ['mv', '%s/copy/etc2/Logo.PNG' % pbucket(2), '%s/copy/etc/logo.png' % pbucket(2)],
    must_find = [ "move: '%s/copy/etc2/Logo.PNG' -> '%s/copy/etc/logo.png'" % (pbucket(2), pbucket(2))])

## ====== Sync between buckets
test_s3cmd("Sync remote2remote", ['sync', '%s/xyz/' % pbucket(1), '%s/copy/' % pbucket(2), '--delete-removed', '--exclude', 'non-printables*'],
    must_find = [ "remote copy: '%s/xyz/demo/dir1/file1-1.txt' -> '%s/copy/demo/dir1/file1-1.txt'" % (pbucket(1), pbucket(2)),
                  "remote copy: 'etc/logo.png' -> 'etc2/Logo.PNG'",
                  "delete: '%s/copy/etc/logo.png'" % pbucket(2) ],
    must_not_find = [ "blah.txt" ])

## ====== Don't Put symbolic link
test_s3cmd("Don't put symbolic links", ['put', 'testsuite/etc/linked1.png', 's3://%s/xyz/' % bucket(1),  '--exclude', 'crappy-file-name/*'],
           retcode = EX_USAGE,
           must_find = ["WARNING: Skipping over symbolic link: testsuite/etc/linked1.png"],
           must_not_find_re = ["^(?!WARNING: Skipping).*linked1.png"])

## ====== Put symbolic link
test_s3cmd("Put symbolic links", ['put', 'testsuite/etc/linked1.png', 's3://%s/xyz/' % bucket(1),'--follow-symlinks' ,  '--exclude', 'crappy-file-name/*'],
           must_find = [ "'testsuite/etc/linked1.png' -> '%s/xyz/linked1.png'" % pbucket(1)])

## ====== Sync symbolic links
test_s3cmd("Sync symbolic links", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--follow-symlinks',  '--exclude', 'crappy-file-name/*' ],
    must_find = ["remote copy: 'etc2/Logo.PNG' -> 'etc/linked.png'"],
           # Don't want to recursively copy linked directories!
           must_not_find_re = ["etc/more/linked-dir/more/give-me-more.txt",
                               "etc/brokenlink.png"],
           retcode = EX_PARTIAL)

## ====== Multi source move
test_s3cmd("Multi-source move", ['mv', '-r', '%s/copy/blahBlah/Blah.txt' % pbucket(2), '%s/copy/etc/' % pbucket(2), '%s/moved/' % pbucket(2)],
    must_find = [ "move: '%s/copy/blahBlah/Blah.txt' -> '%s/moved/Blah.txt'" % (pbucket(2), pbucket(2)),
                  "move: '%s/copy/etc/AtomicClockRadio.ttf' -> '%s/moved/AtomicClockRadio.ttf'" % (pbucket(2), pbucket(2)),
                  "move: '%s/copy/etc/TypeRa.ttf' -> '%s/moved/TypeRa.ttf'" % (pbucket(2), pbucket(2)) ],
    must_not_find = [ "blah.txt" ])

## ====== Verify move
test_s3cmd("Verify move", ['ls', '-r', pbucket(2)],
    must_find = [ "%s/moved/Blah.txt" % pbucket(2),
                  "%s/moved/AtomicClockRadio.ttf" % pbucket(2),
                  "%s/moved/TypeRa.ttf" % pbucket(2),
                  "%s/copy/blahBlah/blah.txt" % pbucket(2) ],
    must_not_find = [ "%s/copy/blahBlah/Blah.txt" % pbucket(2),
                      "%s/copy/etc/AtomicClockRadio.ttf" % pbucket(2),
                      "%s/copy/etc/TypeRa.ttf" % pbucket(2) ])

## ====== List all
test_s3cmd("List all", ['la'],
           must_find = [ "%s/urandom.bin" % pbucket(1)])

## ====== Simple delete
test_s3cmd("Simple delete", ['del', '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    must_find = [ "delete: '%s/xyz/etc2/Logo.PNG'" % pbucket(1) ])

## ====== Simple delete with rm
test_s3cmd("Simple delete with rm", ['rm', '%s/xyz/test_rm/TypeRa.ttf' % pbucket(1)],
    must_find = [ "delete: '%s/xyz/test_rm/TypeRa.ttf'" % pbucket(1) ])

## ====== Create expiration rule with days and prefix
# Minio: disabled
#test_s3cmd("Create expiration rule with days and prefix", ['expire', pbucket(1), '--expiry-days=365', '--expiry-prefix=log/'],
#    must_find = [ "Bucket '%s/': expiration configuration is set." % pbucket(1)])

## ====== Create expiration rule with date and prefix
# Minio: disabled
#test_s3cmd("Create expiration rule with date and prefix", ['expire', pbucket(1), '--expiry-date=2012-12-31T00:00:00.000Z', '--expiry-prefix=log/'],
#    must_find = [ "Bucket '%s/': expiration configuration is set." % pbucket(1)])

## ====== Create expiration rule with days only
# Minio: disabled
#test_s3cmd("Create expiration rule with days only", ['expire', pbucket(1), '--expiry-days=365'],
#    must_find = [ "Bucket '%s/': expiration configuration is set." % pbucket(1)])

## ====== Create expiration rule with date only
# Minio: disabled
#test_s3cmd("Create expiration rule with date only", ['expire', pbucket(1), '--expiry-date=2012-12-31T00:00:00.000Z'],
#    must_find = [ "Bucket '%s/': expiration configuration is set." % pbucket(1)])

## ====== Get current expiration setting
# Minio: disabled
#test_s3cmd("Get current expiration setting", ['info', pbucket(1)],
#    must_find = [ "Expiration Rule: all objects in this bucket will expire in '2012-12-31T00:00:00.000Z'"])

## ====== Delete expiration rule
# Minio: disabled
#test_s3cmd("Delete expiration rule", ['expire', pbucket(1)],
#    must_find = [ "Bucket '%s/': expiration configuration is deleted." % pbucket(1)])

## ====== set Requester Pays flag
# Minio: disabled
#test_s3cmd("Set requester pays", ['payer', '--requester-pays', pbucket(2)])

## ====== get Requester Pays flag
# Minio: disabled
#test_s3cmd("Get requester pays flag", ['info', pbucket(2)],
#    must_find = [ "Payer:     Requester"])

## ====== ls using Requester Pays flag
# Minio: disabled
#test_s3cmd("ls using requester pays flag", ['ls', '--requester-pays', pbucket(2)])

## ====== clear Requester Pays flag
# Minio: disabled
#test_s3cmd("Clear requester pays", ['payer', pbucket(2)])

## ====== get Requester Pays flag
# Minio: disabled
#test_s3cmd("Get requester pays flag", ['info', pbucket(2)],
#    must_find = [ "Payer:     BucketOwner"])

## ====== Recursive delete maximum exceeed
test_s3cmd("Recursive delete maximum exceeded", ['del', '--recursive', '--max-delete=1', '--exclude', 'Atomic*', '%s/xyz/etc' % pbucket(1)],
    must_not_find = [ "delete: '%s/xyz/etc/TypeRa.ttf'" % pbucket(1) ])

## ====== Recursive delete
test_s3cmd("Recursive delete", ['del', '--recursive', '--exclude', 'Atomic*', '%s/xyz/etc' % pbucket(1)],
    must_find = [ "delete: '%s/xyz/etc/TypeRa.ttf'" % pbucket(1) ],
    must_find_re = [ "delete: '.*/etc/logo.png'" ],
    must_not_find = [ "AtomicClockRadio.ttf" ])

## ====== Recursive delete with rm
test_s3cmd("Recursive delete with rm", ['rm', '--recursive', '--exclude', 'Atomic*', '%s/xyz/test_rm' % pbucket(1)],
    must_find = [ "delete: '%s/xyz/test_rm/more/give-me-more.txt'" % pbucket(1) ],
    must_find_re = [ "delete: '.*/test_rm/logo.png'" ],
    must_not_find = [ "AtomicClockRadio.ttf" ])

## ====== Recursive delete all
test_s3cmd("Recursive delete all", ['del', '--recursive', '--force', pbucket(1)],
    must_find_re = [ "delete: '.*binary/random-crap'" ])

## ====== Remove empty bucket
test_s3cmd("Remove empty bucket", ['rb', pbucket(1)],
    must_find = [ "Bucket '%s/' removed" % pbucket(1) ])

## ====== Remove remaining buckets
test_s3cmd("Remove remaining buckets", ['rb', '--recursive', pbucket(2), pbucket(3)],
    must_find = [ "Bucket '%s/' removed" % pbucket(2),
              "Bucket '%s/' removed" % pbucket(3) ])

# vim:et:ts=4:sts=4:ai
