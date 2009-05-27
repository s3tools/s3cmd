#!/usr/bin/env python
# -*- coding=utf-8 -*-

## Amazon S3cmd - testsuite
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import sys
import os
import re
from subprocess import Popen, PIPE, STDOUT
import locale

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
	enc_base_remote = "s3://s3cmd-autotest-1/xyz/%s/" % encoding
	enc_pattern = patterns[encoding]
else:
	print encoding + " specific files not found."

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
		if type(_list) not in [ list, tuple ]:
			_list = [_list]

		if regexps == False:
			_list = [re.escape(item.encode(encoding, "replace")) for item in _list]

		return [re.compile(item, re.MULTILINE) for item in _list]

	global test_counter
	test_counter += 1
	print ("%3d  %s " % (test_counter, label)).ljust(30, "."),
	sys.stdout.flush()

	if run_tests.count(test_counter) == 0 or exclude_tests.count(test_counter) > 0:
		return skip()

	p = Popen(cmd_args, stdout = PIPE, stderr = STDOUT, universal_newlines = True)
	stdout, stderr = p.communicate()
	if retcode != p.returncode:
		return failure("retcode: %d, expected: %d" % (p.returncode, retcode))

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
		cmd = ['mkdir']
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

def test_flushdir(label, dir_name):
	test_rmdir(label + "(rm)", dir_name)
	return test_mkdir(label + "(mk)", dir_name)

argv = sys.argv[1:]
while argv:
	arg = argv.pop(0)
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

## ====== Remove test buckets
test_s3cmd("Remove test buckets", ['rb', '-r', 's3://s3cmd-autotest-1', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'],
	must_find = [ "Bucket 's3://s3cmd-autotest-1/' removed",
		      "Bucket 's3://s3cmd-autotest-2/' removed",
		      "Bucket 's3://s3cmd-Autotest-3/' removed" ])


## ====== Create one bucket (EU)
test_s3cmd("Create one bucket (EU)", ['mb', '--bucket-location=EU', 's3://s3cmd-autotest-1'], 
	must_find = "Bucket 's3://s3cmd-autotest-1/' created")



## ====== Create multiple buckets
test_s3cmd("Create multiple buckets", ['mb', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'], 
	must_find = [ "Bucket 's3://s3cmd-autotest-2/' created", "Bucket 's3://s3cmd-Autotest-3/' created" ])


## ====== Invalid bucket name
test_s3cmd("Invalid bucket name", ["mb", "--bucket-location=EU", "s3://s3cmd-Autotest-EU"], 
	retcode = 1,
	must_find = "ERROR: Parameter problem: Bucket name 's3cmd-Autotest-EU' contains disallowed character", 
	must_not_find_re = "Bucket.*created")


## ====== Buckets list
test_s3cmd("Buckets list", ["ls"], 
	must_find = [ "autotest-1", "autotest-2", "Autotest-3" ], must_not_find_re = "Autotest-EU")


## ====== Sync to S3
test_s3cmd("Sync to S3", ['sync', 'testsuite/', 's3://s3cmd-autotest-1/xyz/', '--exclude', '.svn/*', '--exclude', '*.png', '--no-encrypt', '--exclude-from', 'testsuite/exclude.encodings' ],
	must_not_find_re = [ "\.svn/", "\.png$" ])

if have_encoding:
	## ====== Sync UTF-8 / GBK / ... to S3
	test_s3cmd("Sync %s to S3" % encoding, ['sync', 'testsuite/encodings/' + encoding, 's3://s3cmd-autotest-1/xyz/encodings/', '--exclude', '.svn/*', '--no-encrypt' ],
		must_find = [ u"File 'testsuite/encodings/%(encoding)s/%(pattern)s' stored as 's3://s3cmd-autotest-1/xyz/encodings/%(encoding)s/%(pattern)s'" % { 'encoding' : encoding, 'pattern' : enc_pattern } ])


## ====== List bucket content
must_find_re = [ u"DIR   s3://s3cmd-autotest-1/xyz/binary/$", u"DIR   s3://s3cmd-autotest-1/xyz/etc/$" ]
must_not_find = [ u"random-crap.md5", u".svn" ]
test_s3cmd("List bucket content", ['ls', 's3://s3cmd-autotest-1/xyz/'],
	must_find_re = must_find_re,
	must_not_find = must_not_find)


## ====== List bucket recursive
must_find = [ u"s3://s3cmd-autotest-1/xyz/binary/random-crap.md5" ]
if have_encoding:
	must_find.append(u"s3://s3cmd-autotest-1/xyz/encodings/%(encoding)s/%(pattern)s" % { 'encoding' : encoding, 'pattern' : enc_pattern })
test_s3cmd("List bucket recursive", ['ls', '--recursive', 's3://s3cmd-autotest-1'],
	must_find = must_find,
	must_not_find = [ "logo.png" ])

## ====== FIXME
# test_s3cmd("Recursive put", ['put', '--recursive', 'testsuite/etc', 's3://s3cmd-autotest-1/xyz/'])


## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")


## ====== Sync from S3
must_find = [ "File 's3://s3cmd-autotest-1/xyz/binary/random-crap.md5' stored as 'testsuite-out/xyz/binary/random-crap.md5'" ]
if have_encoding:
	must_find.append(u"File 's3://s3cmd-autotest-1/xyz/encodings/%(encoding)s/%(pattern)s' stored as 'testsuite-out/xyz/encodings/%(encoding)s/%(pattern)s' " % { 'encoding' : encoding, 'pattern' : enc_pattern })
test_s3cmd("Sync from S3", ['sync', 's3://s3cmd-autotest-1/xyz', 'testsuite-out'],
	must_find = must_find)


## ====== Clean up local destination dir
test_flushdir("Clean testsuite-out/", "testsuite-out")


## ====== Put public, guess MIME
test_s3cmd("Put public, guess MIME", ['put', '--guess-mime-type', '--acl-public', 'testsuite/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc/logo.png'],
	must_find = [ "stored as 's3://s3cmd-autotest-1/xyz/etc/logo.png'" ])


## ====== Retrieve from URL
if have_wget:
	test("Retrieve from URL", ['wget', '-O', 'testsuite-out/logo.png', 'http://s3cmd-autotest-1.s3.amazonaws.com/xyz/etc/logo.png'],
		must_find_re = [ 'logo.png.*saved \[22059/22059\]' ])


## ====== Change ACL to Private
test_s3cmd("Change ACL to Private", ['setacl', '--acl-private', 's3://s3cmd-autotest-1/xyz/etc/l*.png'],
	must_find = [ "logo.png: ACL set to Private" ])


## ====== Verify Private ACL
if have_wget:
	test("Verify Private ACL", ['wget', '-O', 'testsuite-out/logo.png', 'http://s3cmd-autotest-1.s3.amazonaws.com/xyz/etc/logo.png'],
		retcode = 1,
		must_find_re = [ 'ERROR 403: Forbidden' ])


## ====== Change ACL to Public
test_s3cmd("Change ACL to Public", ['setacl', '--acl-public', '--recursive', 's3://s3cmd-autotest-1/xyz/etc/', '-v'],
	must_find = [ "logo.png: ACL set to Public" ])


## ====== Verify Public ACL
if have_wget:
	test("Verify Public ACL", ['wget', '-O', 'testsuite-out/logo.png', 'http://s3cmd-autotest-1.s3.amazonaws.com/xyz/etc/logo.png'],
		must_find_re = [ 'logo.png.*saved \[22059/22059\]' ])


## ====== Sync more to S3
test_s3cmd("Sync more to S3", ['sync', 'testsuite/', 's3://s3cmd-autotest-1/xyz/', '--no-encrypt' ],
	must_find = [ "File 'testsuite/.svn/format' stored as 's3://s3cmd-autotest-1/xyz/.svn/format' " ])


## ====== Rename within S3
test_s3cmd("Rename within S3", ['mv', 's3://s3cmd-autotest-1/xyz/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	must_find = [ 'File s3://s3cmd-autotest-1/xyz/etc/logo.png moved to s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG' ])


## ====== Rename (NoSuchKey)
test_s3cmd("Rename (NoSuchKey)", ['mv', 's3://s3cmd-autotest-1/xyz/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	retcode = 1,
	must_find_re = [ 'ERROR:.*NoSuchKey' ],
	must_not_find = [ 'File s3://s3cmd-autotest-1/xyz/etc/logo.png moved to s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG' ])


## ====== Sync more from S3
test_s3cmd("Sync more from S3", ['sync', '--delete-removed', 's3://s3cmd-autotest-1/xyz', 'testsuite-out'],
	must_find = [ "deleted: testsuite-out/logo.png",
	              "File 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG' stored as 'testsuite-out/xyz/etc2/Logo.PNG' (22059 bytes", 
	              "File 's3://s3cmd-autotest-1/xyz/.svn/format' stored as 'testsuite-out/xyz/.svn/format' " ],
	must_not_find_re = [ "not-deleted.*etc/logo.png" ])


## ====== Make dst dir for get
test_rmdir("Remove dst dir for get", "testsuite-out")


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG', 's3://s3cmd-autotest-1/xyz/etc/AtomicClockRadio.ttf', 'testsuite-out'],
	retcode = 1,
	must_find = [ 'Destination must be a directory when downloading multiple sources.' ])


## ====== Make dst dir for get
test_mkdir("Make dst dir for get", "testsuite-out")


## ====== Get multiple files
test_s3cmd("Get multiple files", ['get', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG', 's3://s3cmd-autotest-1/xyz/etc/AtomicClockRadio.ttf', 'testsuite-out'],
	must_find = [ u"saved as 'testsuite-out/Logo.PNG'", u"saved as 'testsuite-out/AtomicClockRadio.ttf'" ])

## ====== Upload files differing in capitalisation
test_s3cmd("blah.txt / Blah.txt", ['put', '-r', 'testsuite/blahBlah', 's3://s3cmd-autotest-1/'],
	must_find = [ 's3://s3cmd-autotest-1/blahBlah/Blah.txt', 's3://s3cmd-autotest-1/blahBlah/blah.txt' ])

## ====== Copy between buckets
test_s3cmd("Copy between buckets", ['cp', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG', 's3://s3cmd-Autotest-3/xyz/etc2/logo.png'],
	must_find = [ "File s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG copied to s3://s3cmd-Autotest-3/xyz/etc2/logo.png" ])

## ====== Recursive copy
test_s3cmd("Recursive copy, set ACL", ['cp', '-r', '--acl-public', 's3://s3cmd-autotest-1/xyz/', 's3://s3cmd-autotest-2/copy', '--exclude', '.svn/*'],
	must_find = [ "File s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG copied to s3://s3cmd-autotest-2/copy/etc2/Logo.PNG",
	              "File s3://s3cmd-autotest-1/xyz/blahBlah/Blah.txt copied to s3://s3cmd-autotest-2/copy/blahBlah/Blah.txt",
	              "File s3://s3cmd-autotest-1/xyz/blahBlah/blah.txt copied to s3://s3cmd-autotest-2/copy/blahBlah/blah.txt" ],
	must_not_find = [ ".svn" ])

## ====== Verify ACL and MIME type
test_s3cmd("Verify ACL and MIME type", ['info', 's3://s3cmd-autotest-2/copy/etc2/Logo.PNG' ],
	must_find_re = [ "MIME type:.*image/png", 
	                 "ACL:.*\*anon\*: READ",
					 "URL:.*http://s3cmd-autotest-2.s3.amazonaws.com/copy/etc2/Logo.PNG" ])

## ====== Multi source move
test_s3cmd("Multi-source move", ['mv', '-r', 's3://s3cmd-autotest-2/copy/blahBlah/Blah.txt', 's3://s3cmd-autotest-2/copy/etc/', 's3://s3cmd-autotest-2/moved/'],
	must_find = [ "File s3://s3cmd-autotest-2/copy/blahBlah/Blah.txt moved to s3://s3cmd-autotest-2/moved/Blah.txt",
	              "File s3://s3cmd-autotest-2/copy/etc/AtomicClockRadio.ttf moved to s3://s3cmd-autotest-2/moved/AtomicClockRadio.ttf",
				  "File s3://s3cmd-autotest-2/copy/etc/TypeRa.ttf moved to s3://s3cmd-autotest-2/moved/TypeRa.ttf" ],
	must_not_find = [ "blah.txt" ])

## ====== Verify move
test_s3cmd("Verify move", ['ls', '-r', 's3://s3cmd-autotest-2'],
	must_find = [ "s3://s3cmd-autotest-2/moved/Blah.txt",
	              "s3://s3cmd-autotest-2/moved/AtomicClockRadio.ttf",
				  "s3://s3cmd-autotest-2/moved/TypeRa.ttf",
				  "s3://s3cmd-autotest-2/copy/blahBlah/blah.txt" ],
	must_not_find = [ "s3://s3cmd-autotest-2/copy/blahBlah/Blah.txt",
					  "s3://s3cmd-autotest-2/copy/etc/AtomicClockRadio.ttf",
					  "s3://s3cmd-autotest-2/copy/etc/TypeRa.ttf" ])

## ====== Simple delete
test_s3cmd("Simple delete", ['del', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	must_find = [ "File s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG deleted" ])


## ====== Recursive delete
test_s3cmd("Recursive delete", ['del', '--recursive', '--exclude', 'Atomic*', 's3://s3cmd-autotest-1/xyz/etc'],
	must_find = [ "File s3://s3cmd-autotest-1/xyz/etc/TypeRa.ttf deleted" ],
	must_find_re = [ "File .*\.svn/format deleted" ],
	must_not_find = [ "AtomicClockRadio.ttf" ])

## ====== Recursive delete all
test_s3cmd("Recursive delete all", ['del', '--recursive', '--force', 's3://s3cmd-autotest-1'],
	must_find_re = [ "File .*binary/random-crap deleted" ])


## ====== Remove empty bucket
test_s3cmd("Remove empty bucket", ['rb', 's3://s3cmd-autotest-1'],
	must_find = [ "Bucket 's3://s3cmd-autotest-1/' removed" ])


## ====== Remove remaining buckets
test_s3cmd("Remove remaining buckets", ['rb', '--recursive', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'],
	must_find = [ "Bucket 's3://s3cmd-autotest-2/' removed",
		      "Bucket 's3://s3cmd-Autotest-3/' removed" ])
