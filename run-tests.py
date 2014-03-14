#!/usr/bin/env python
# -*- coding=utf-8 -*-

## Amazon S3cmd - testsuite
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

import sys
import os
import re
from subprocess import Popen, PIPE, STDOUT
import locale
import getpass
import S3.Exceptions
import S3.Config

count_pass = 0
count_fail = 0
count_skip = 0

test_counter = 0
run_tests = []
exclude_tests = []

verbose = False

if os.name == "posix":
    have_wget = True
elif os.name == "nt":
    have_wget = False
else:
    print "Unknown platform: %s" % os.name
    sys.exit(1)

config_file = None
if os.getenv("HOME"):
    config_file = os.path.join(os.getenv("HOME"), ".s3cfg")
elif os.name == "nt" and os.getenv("USERPROFILE"):
    config_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), "Application Data", "s3cmd.ini")

cfg = S3.Config.Config(config_file)

## Unpack testsuite/ directory
if not os.path.isdir('testsuite') and os.path.isfile('testsuite.tar.gz'):
    os.system("tar -xz -f testsuite.tar.gz")
if not os.path.isdir('testsuite'):
    print "Something went wrong while unpacking testsuite.tar.gz"
    sys.exit(1)

os.system("tar -xf testsuite/checksum.tar -C testsuite")
if not os.path.isfile('testsuite/checksum/cksum33.txt'):
    print "Something went wrong while unpacking testsuite/checkum.tar"
    sys.exit(1)

## Fix up permissions for permission-denied tests
os.chmod("testsuite/permission-tests/permission-denied-dir", 0444)
os.chmod("testsuite/permission-tests/permission-denied.txt", 0000)

## Patterns for Unicode tests
patterns = {}
patterns['UTF-8'] = u"ŪņЇЌœđЗ/☺ unicode € rocks ™"
patterns['GBK'] = u"12月31日/1-特色條目"

encoding = locale.getpreferredencoding()
if not encoding:
    print "Guessing current system encoding failed. Consider setting $LANG variable."
    sys.exit(1)
else:
    print "System encoding: " + encoding

have_encoding = os.path.isdir('testsuite/encodings/' + encoding)
if not have_encoding and os.path.isfile('testsuite/encodings/%s.tar.gz' % encoding):
    os.system("tar xvz -C testsuite/encodings -f testsuite/encodings/%s.tar.gz" % encoding)
    have_encoding = os.path.isdir('testsuite/encodings/' + encoding)

if have_encoding:
    #enc_base_remote = "%s/xyz/%s/" % (pbucket(1), encoding)
    enc_pattern = patterns[encoding]
else:
    print encoding + " specific files not found."

if not os.path.isdir('testsuite/crappy-file-name'):
    os.system("tar xvz -C testsuite -f testsuite/crappy-file-name.tar.gz")
    # TODO: also unpack if the tarball is newer than the directory timestamp
    #       for instance when a new version was pulled from SVN.

def test(label, cmd_args = [], retcode = 0, must_find = [], must_not_find = [], must_find_re = [], must_not_find_re = []):
    def command_output():
        print "----"
        print " ".join([arg.find(" ")>=0 and "'%s'" % arg or arg for arg in cmd_args])
        print "----"
        print stdout
        print "----"

    def failure(message = ""):
        global count_fail
        if message:
            message = "  (%r)" % message
        print "\x1b[31;1mFAIL%s\x1b[0m" % (message)
        count_fail += 1
        command_output()
        #return 1
        sys.exit(1)
    def success(message = ""):
        global count_pass
        if message:
            message = "  (%r)" % message
        print "\x1b[32;1mOK\x1b[0m%s" % (message)
        count_pass += 1
        if verbose:
            command_output()
        return 0
    def skip(message = ""):
        global count_skip
        if message:
            message = "  (%r)" % message
        print "\x1b[33;1mSKIP\x1b[0m%s" % (message)
        count_skip += 1
        return 0
    def compile_list(_list, regexps = False):
        if regexps == False:
            _list = [re.escape(item.encode(encoding, "replace")) for item in _list]

        return [re.compile(item, re.MULTILINE) for item in _list]

    global test_counter
    test_counter += 1
    print ("%3d  %s " % (test_counter, label)).ljust(30, "."),
    sys.stdout.flush()

    if run_tests.count(test_counter) == 0 or exclude_tests.count(test_counter) > 0:
        return skip()

    if not cmd_args:
        return skip()

    p = Popen(cmd_args, stdout = PIPE, stderr = STDOUT, universal_newlines = True)
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

    return test(label, cmd_args, **kwargs)

def test_mkdir(label, dir_name):
    if os.name in ("posix", "nt"):
        cmd = ['mkdir', '-p']
    else:
        print "Unknown platform: %s" % os.name
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
            print "Unknown platform: %s" % os.name
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
        print "Unknown platform: %s" % os.name
        sys.exit(1)
    cmd.append(src_file)
    cmd.append(dst_file)
    return test(label, cmd)

bucket_prefix = u"%s-" % getpass.getuser()
print "Using bucket prefix: '%s'" % bucket_prefix

argv = sys.argv[1:]
while argv:
    arg = argv.pop(0)
    if arg.startswith('--bucket-prefix='):
        print "Usage: '--bucket-prefix PREFIX', not '--bucket-prefix=PREFIX'"
        sys.exit(0)
    if arg in ("-h", "--help"):
        print "%s A B K..O -N" % sys.argv[0]
        print "Run tests number A, B and K through to O, except for N"
        sys.exit(0)
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
            print "Bucket prefix option must explicitly supply a bucket name prefix"
            sys.exit(0)
        continue
    if arg.find("..") >= 0:
        range_idx = arg.find("..")
        range_start = arg[:range_idx] or 0
        range_end = arg[range_idx+2:] or 999
        run_tests.extend(range(int(range_start), int(range_end) + 1))
    elif arg.startswith("-"):
        exclude_tests.append(int(arg[1:]))
    else:
        run_tests.append(int(arg))

if not run_tests:
    run_tests = range(0, 999)

# helper functions for generating bucket names
def bucket(tail):
        '''Test bucket name'''
        label = 'autotest'
        if str(tail) == '3':
                label = 'Autotest'
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
test_s3cmd("Create one bucket (EU)", ['mb', '--bucket-location=EU', pbucket(1)],
    must_find = "Bucket '%s/' created" % pbucket(1))



## ====== Create multiple buckets
test_s3cmd("Create multiple buckets", ['mb', pbucket(2), pbucket(3)],
    must_find = [ "Bucket '%s/' created" % pbucket(2), "Bucket '%s/' created" % pbucket(3)])


## ====== Invalid bucket name
test_s3cmd("Invalid bucket name", ["mb", "--bucket-location=EU", pbucket('EU')],
    retcode = 1,
    must_find = "ERROR: Parameter problem: Bucket name '%s' contains disallowed character" % bucket('EU'),
    must_not_find_re = "Bucket.*created")


## ====== Buckets list
test_s3cmd("Buckets list", ["ls"],
    must_find = [ "autotest-1", "autotest-2", "Autotest-3" ], must_not_find_re = "autotest-EU")


## ====== Sync to S3
test_s3cmd("Sync to S3", ['sync', 'testsuite/', pbucket(1) + '/xyz/', '--exclude', 'demo/*', '--exclude', '*.png', '--no-encrypt', '--exclude-from', 'testsuite/exclude.encodings' ],
    must_find = [ "WARNING: 32 non-printable characters replaced in: crappy-file-name/non-printables ^A^B^C^D^E^F^G^H^I^J^K^L^M^N^O^P^Q^R^S^T^U^V^W^X^Y^Z^[^\^]^^^_^? +-[\]^<>%%\"'#{}`&?.end",
                  "WARNING: File can not be uploaded: testsuite/permission-tests/permission-denied.txt: Permission denied",
                  "stored as '%s/xyz/crappy-file-name/non-printables ^A^B^C^D^E^F^G^H^I^J^K^L^M^N^O^P^Q^R^S^T^U^V^W^X^Y^Z^[^\^]^^^_^? +-[\\]^<>%%%%\"'#{}`&?.end'" % pbucket(1) ],
    must_not_find_re = [ "demo/", "\.png$", "permission-denied-dir" ])

if have_encoding:
    ## ====== Sync UTF-8 / GBK / ... to S3
    test_s3cmd("Sync %s to S3" % encoding, ['sync', 'testsuite/encodings/' + encoding, '%s/xyz/encodings/' % pbucket(1), '--exclude', 'demo/*', '--no-encrypt' ],
        must_find = [ u"File 'testsuite/encodings/%(encoding)s/%(pattern)s' stored as '%(pbucket)s/xyz/encodings/%(encoding)s/%(pattern)s'" % { 'encoding' : encoding, 'pattern' : enc_pattern , 'pbucket' : pbucket(1)} ])


## ====== List bucket content
test_s3cmd("List bucket content", ['ls', '%s/xyz/' % pbucket(1) ],
    must_find_re = [ u"DIR   %s/xyz/binary/$" % pbucket(1) , u"DIR   %s/xyz/etc/$" % pbucket(1) ],
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


## ====== Sync from S3
must_find = [ "File '%s/xyz/binary/random-crap.md5' stored as 'testsuite-out/xyz/binary/random-crap.md5'" % pbucket(1) ]
if have_encoding:
    must_find.append(u"File '%(pbucket)s/xyz/encodings/%(encoding)s/%(pattern)s' stored as 'testsuite-out/xyz/encodings/%(encoding)s/%(pattern)s' " % { 'encoding' : encoding, 'pattern' : enc_pattern, 'pbucket' : pbucket(1) })
test_s3cmd("Sync from S3", ['sync', '%s/xyz' % pbucket(1), 'testsuite-out'],
    must_find = must_find)


## ====== Remove 'demo' directory
test_rmdir("Remove 'dir-test/'", "testsuite-out/xyz/dir-test/")


## ====== Create dir with name of a file
test_mkdir("Create file-dir dir", "testsuite-out/xyz/dir-test/file-dir")


## ====== Skip dst dirs
test_s3cmd("Skip over dir", ['sync', '%s/xyz' % pbucket(1), 'testsuite-out'],
    must_find = "WARNING: testsuite-out/xyz/dir-test/file-dir is a directory - skipping over")


## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")


## ====== Put public, guess MIME
test_s3cmd("Put public, guess MIME", ['put', '--guess-mime-type', '--acl-public', 'testsuite/etc/logo.png', '%s/xyz/etc/logo.png' % pbucket(1)],
    must_find = [ "stored as '%s/xyz/etc/logo.png'" % pbucket(1) ])


## ====== Retrieve from URL
if have_wget:
    test("Retrieve from URL", ['wget', '-O', 'testsuite-out/logo.png', 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base)],
        must_find_re = [ 'logo.png.*saved \[22059/22059\]' ])


## ====== Change ACL to Private
test_s3cmd("Change ACL to Private", ['setacl', '--acl-private', '%s/xyz/etc/l*.png' % pbucket(1)],
    must_find = [ "logo.png: ACL set to Private" ])


## ====== Verify Private ACL
if have_wget:
    test("Verify Private ACL", ['wget', '-O', 'testsuite-out/logo.png', 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base)],
         retcode = [1, 8],
         must_find_re = [ 'ERROR 403: Forbidden' ])


## ====== Change ACL to Public
test_s3cmd("Change ACL to Public", ['setacl', '--acl-public', '--recursive', '%s/xyz/etc/' % pbucket(1) , '-v'],
    must_find = [ "logo.png: ACL set to Public" ])


## ====== Verify Public ACL
if have_wget:
    test("Verify Public ACL", ['wget', '-O', 'testsuite-out/logo.png', 'http://%s.%s/xyz/etc/logo.png' % (bucket(1), cfg.host_base)],
        must_find_re = [ 'logo.png.*saved \[22059/22059\]' ])


## ====== Sync more to S3
test_s3cmd("Sync more to S3", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt' ],
    must_find = [ "File 'testsuite/demo/some-file.xml' stored as '%s/xyz/demo/some-file.xml' " % pbucket(1) ],
    must_not_find = [ "File 'testsuite/etc/linked.png' stored as '%s/xyz/etc/linked.png" % pbucket(1) ])


## ====== Don't check MD5 sum on Sync
test_copy("Change file cksum1.txt", "testsuite/checksum/cksum2.txt", "testsuite/checksum/cksum1.txt")
test_copy("Change file cksum33.txt", "testsuite/checksum/cksum2.txt", "testsuite/checksum/cksum33.txt")
test_s3cmd("Don't check MD5", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--no-check-md5'],
    must_find = [ "cksum33.txt" ],
    must_not_find = [ "cksum1.txt" ])


## ====== Check MD5 sum on Sync
test_s3cmd("Check MD5", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--check-md5'],
    must_find = [ "cksum1.txt" ])


## ====== Rename within S3
test_s3cmd("Rename within S3", ['mv', '%s/xyz/etc/logo.png' % pbucket(1), '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    must_find = [ 'File %s/xyz/etc/logo.png moved to %s/xyz/etc2/Logo.PNG' % (pbucket(1), pbucket(1))])


## ====== Rename (NoSuchKey)
test_s3cmd("Rename (NoSuchKey)", ['mv', '%s/xyz/etc/logo.png' % pbucket(1), '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    retcode = 1,
    must_find_re = [ 'ERROR:.*NoSuchKey' ],
    must_not_find = [ 'File %s/xyz/etc/logo.png moved to %s/xyz/etc2/Logo.PNG' % (pbucket(1), pbucket(1)) ])

## ====== Sync more from S3 (invalid src)
test_s3cmd("Sync more from S3 (invalid src)", ['sync', '--delete-removed', '%s/xyz/DOESNOTEXIST' % pbucket(1), 'testsuite-out'],
    must_not_find = [ "deleted: testsuite-out/logo.png" ])

## ====== Sync more from S3
test_s3cmd("Sync more from S3", ['sync', '--delete-removed', '%s/xyz' % pbucket(1), 'testsuite-out'],
    must_find = [ "deleted: testsuite-out/logo.png",
                  "File '%s/xyz/etc2/Logo.PNG' stored as 'testsuite-out/xyz/etc2/Logo.PNG' (22059 bytes" % pbucket(1),
                  "File '%s/xyz/demo/some-file.xml' stored as 'testsuite-out/xyz/demo/some-file.xml' " % pbucket(1) ],
    must_not_find_re = [ "not-deleted.*etc/logo.png" ])


## ====== Make dst dir for get
test_rmdir("Remove dst dir for get", "testsuite-out")


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc/AtomicClockRadio.ttf' % pbucket(1), 'testsuite-out'],
    retcode = 1,
    must_find = [ 'Destination must be a directory or stdout when downloading multiple sources.' ])


## ====== Make dst dir for get
test_mkdir("Make dst dir for get", "testsuite-out")


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc/AtomicClockRadio.ttf' % pbucket(1), 'testsuite-out'],
    must_find = [ u"saved as 'testsuite-out/Logo.PNG'", u"saved as 'testsuite-out/AtomicClockRadio.ttf'" ])

## ====== Upload files differing in capitalisation
test_s3cmd("blah.txt / Blah.txt", ['put', '-r', 'testsuite/blahBlah', pbucket(1)],
    must_find = [ '%s/blahBlah/Blah.txt' % pbucket(1), '%s/blahBlah/blah.txt' % pbucket(1)])

## ====== Copy between buckets
test_s3cmd("Copy between buckets", ['cp', '%s/xyz/etc2/Logo.PNG' % pbucket(1), '%s/xyz/etc2/logo.png' % pbucket(3)],
    must_find = [ "File %s/xyz/etc2/Logo.PNG copied to %s/xyz/etc2/logo.png" % (pbucket(1), pbucket(3)) ])

## ====== Recursive copy
test_s3cmd("Recursive copy, set ACL", ['cp', '-r', '--acl-public', '%s/xyz/' % pbucket(1), '%s/copy' % pbucket(2), '--exclude', 'demo/dir?/*.txt', '--exclude', 'non-printables*'],
    must_find = [ "File %s/xyz/etc2/Logo.PNG copied to %s/copy/etc2/Logo.PNG" % (pbucket(1), pbucket(2)),
                  "File %s/xyz/blahBlah/Blah.txt copied to %s/copy/blahBlah/Blah.txt" % (pbucket(1), pbucket(2)),
                  "File %s/xyz/blahBlah/blah.txt copied to %s/copy/blahBlah/blah.txt" % (pbucket(1), pbucket(2)) ],
    must_not_find = [ "demo/dir1/file1-1.txt" ])

## ====== Verify ACL and MIME type
test_s3cmd("Verify ACL and MIME type", ['info', '%s/copy/etc2/Logo.PNG' % pbucket(2) ],
    must_find_re = [ "MIME type:.*image/png",
                     "ACL:.*\*anon\*: READ",
                     "URL:.*http://%s.%s/copy/etc2/Logo.PNG" % (bucket(2), cfg.host_base) ])

## ====== Rename within S3
test_s3cmd("Rename within S3", ['mv', '%s/copy/etc2/Logo.PNG' % pbucket(2), '%s/copy/etc/logo.png' % pbucket(2)],
    must_find = [ 'File %s/copy/etc2/Logo.PNG moved to %s/copy/etc/logo.png' % (pbucket(2), pbucket(2))])

## ====== Sync between buckets
test_s3cmd("Sync remote2remote", ['sync', '%s/xyz/' % pbucket(1), '%s/copy/' % pbucket(2), '--delete-removed', '--exclude', 'non-printables*'],
    must_find = [ "File %s/xyz/demo/dir1/file1-1.txt copied to %s/copy/demo/dir1/file1-1.txt" % (pbucket(1), pbucket(2)),
                  "remote copy: etc/logo.png -> etc2/Logo.PNG",
                  "File %s/copy/etc/logo.png deleted" % pbucket(2) ],
    must_not_find = [ "blah.txt" ])

## ====== Don't Put symbolic link
test_s3cmd("Don't put symbolic links", ['put', 'testsuite/etc/linked1.png', 's3://%s/xyz/' % bucket(1),],
    must_not_find_re = [ "linked1.png"])

## ====== Put symbolic link
test_s3cmd("Put symbolic links", ['put', 'testsuite/etc/linked1.png', 's3://%s/xyz/' % bucket(1),'--follow-symlinks' ],
           must_find = [ "File 'testsuite/etc/linked1.png' stored as '%s/xyz/linked1.png'" % pbucket(1)])

## ====== Sync symbolic links
test_s3cmd("Sync symbolic links", ['sync', 'testsuite/', 's3://%s/xyz/' % bucket(1), '--no-encrypt', '--follow-symlinks' ],
    must_find = ["remote copy: etc2/Logo.PNG -> etc/linked.png"],
           # Don't want to recursively copy linked directories!
           must_not_find_re = ["etc/more/linked-dir/more/give-me-more.txt",
                               "etc/brokenlink.png"],
           )

## ====== Multi source move
test_s3cmd("Multi-source move", ['mv', '-r', '%s/copy/blahBlah/Blah.txt' % pbucket(2), '%s/copy/etc/' % pbucket(2), '%s/moved/' % pbucket(2)],
    must_find = [ "File %s/copy/blahBlah/Blah.txt moved to %s/moved/Blah.txt" % (pbucket(2), pbucket(2)),
                  "File %s/copy/etc/AtomicClockRadio.ttf moved to %s/moved/AtomicClockRadio.ttf" % (pbucket(2), pbucket(2)),
                  "File %s/copy/etc/TypeRa.ttf moved to %s/moved/TypeRa.ttf" % (pbucket(2), pbucket(2)) ],
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

## ====== Simple delete
test_s3cmd("Simple delete", ['del', '%s/xyz/etc2/Logo.PNG' % pbucket(1)],
    must_find = [ "File %s/xyz/etc2/Logo.PNG deleted" % pbucket(1) ])


## ====== Recursive delete maximum exceeed
test_s3cmd("Recursive delete maximum exceeded", ['del', '--recursive', '--max-delete=1', '--exclude', 'Atomic*', '%s/xyz/etc' % pbucket(1)],
    must_not_find = [ "File %s/xyz/etc/TypeRa.ttf deleted" % pbucket(1) ])

## ====== Recursive delete
test_s3cmd("Recursive delete", ['del', '--recursive', '--exclude', 'Atomic*', '%s/xyz/etc' % pbucket(1)],
    must_find = [ "File %s/xyz/etc/TypeRa.ttf deleted" % pbucket(1) ],
    must_find_re = [ "File .*/etc/logo.png deleted" ],
    must_not_find = [ "AtomicClockRadio.ttf" ])

## ====== Recursive delete all
test_s3cmd("Recursive delete all", ['del', '--recursive', '--force', pbucket(1)],
    must_find_re = [ "File .*binary/random-crap deleted" ])


## ====== Remove empty bucket
test_s3cmd("Remove empty bucket", ['rb', pbucket(1)],
    must_find = [ "Bucket '%s/' removed" % pbucket(1) ])


## ====== Remove remaining buckets
test_s3cmd("Remove remaining buckets", ['rb', '--recursive', pbucket(2), pbucket(3)],
    must_find = [ "Bucket '%s/' removed" % pbucket(2),
              "Bucket '%s/' removed" % pbucket(3) ])

# vim:et:ts=4:sts=4:ai
