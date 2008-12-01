#!/usr/bin/env python
# -*- coding=utf-8 -*-

## Amazon S3cmd - testsuite
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import sys
import re
from subprocess import Popen, PIPE, STDOUT

count_pass = 0
count_fail = 0

def test(label, cmd_args = [], retcode = 0, must_find = [], must_not_find = [], must_find_re = [], must_not_find_re = []):
	def failure(message = ""):
		global count_fail
		if message:
			message = "  (%s)" % message
		print "\x1b[31;1mFAIL%s\x1b[0m" % (message)
		count_fail += 1
		print "----"
		print " ".join([arg.find(" ")>=0 and "'%s'" % arg or arg for arg in cmd_args])
		print "----"
		print stdout
		print "----"
		return 1
	def success(message = ""):
		global count_pass
		if message:
			message = "  (%s)" % message
		print "\x1b[32;1mOK\x1b[0m%s" % (message)
		count_pass += 1
		return 0
	def compile_list(_list, regexps = False):
		if type(_list) not in [ list, tuple ]:
			_list = [_list]

		if regexps == False:
			_list = [re.escape(item.encode("utf-8")) for item in _list]

		return [re.compile(item) for item in _list]
	
	print (label + " ").ljust(30, "."),
	sys.stdout.flush()

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
		cmd_args.insert(0, "./s3cmd")
	return test(label, cmd_args, **kwargs)

test_s3cmd("Remove test buckets", ['rb', '-r', 's3://s3cmd-autotest-1', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'],
	must_find = [ "Bucket 's3://s3cmd-autotest-1/' removed",
		      "Bucket 's3://s3cmd-autotest-2/' removed",
		      "Bucket 's3://s3cmd-Autotest-3/' removed" ])

test_s3cmd("Create one bucket (EU)", ['mb', '--bucket-location=EU', 's3://s3cmd-autotest-1'], 
	must_find = "Bucket 's3://s3cmd-autotest-1/' created")

test_s3cmd("Create multiple buckets", ['mb', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'], 
	must_find = [ "Bucket 's3://s3cmd-autotest-2/' created", "Bucket 's3://s3cmd-Autotest-3/' created" ])

test_s3cmd("Invalid bucket name", ["mb", "--bucket-location=EU", "s3://s3cmd-Autotest-EU"], 
	retcode = 1,
	must_find = "ERROR: Parameter problem: Bucket name 's3cmd-Autotest-EU' contains disallowed character", 
	must_not_find_re = "Bucket.*created")

test_s3cmd("Buckets list", ["ls"], 
	must_find = [ "autotest-1", "autotest-2", "Autotest-3" ], must_not_find_re = "Autotest-EU")

test_s3cmd("Sync to S3", ['sync', 'testsuite', 's3://s3cmd-autotest-1/xyz/', '--exclude', '.svn/*', '--exclude', '*.png', '--no-encrypt'])

test_s3cmd("Check bucket content (-r)", ['ls', '--recursive', 's3://s3cmd-autotest-1'],
	must_find = [ u"s3://s3cmd-autotest-1/xyz/unicode/ŪņЇЌœđЗ/☺ unicode € rocks ™" ],
	must_not_find = [ "logo.png" ])

test_s3cmd("Check bucket content", ['ls', 's3://s3cmd-autotest-1/xyz/'],
	must_find_re = [ u"D s3://s3cmd-autotest-1/xyz/unicode/$" ],
	must_not_find = [ u"ŪņЇЌœđЗ/☺ unicode € rocks ™" ])

# test_s3cmd("Recursive put", ['put', '--recursive', 'testsuite/etc', 's3://s3cmd-autotest-1/xyz/'])

test_s3cmd("Put public, guess MIME", ['put', '--guess-mime-type', '--acl-public', 'testsuite/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc/logo.png'],
	must_find = [ "stored as s3://s3cmd-autotest-1/xyz/etc/logo.png" ])

test("Removing local target", ['rm', '-rf', 'testsuite-out'])

test_s3cmd("Sync from S3", ['sync', 's3://s3cmd-autotest-1/xyz', 'testsuite-out'],
	must_find = [ "stored as testsuite-out/etc/logo.png ", u"unicode/ŪņЇЌœđЗ/☺ unicode € rocks ™" ])

test("Retrieve public URL", ['wget', 'http://s3cmd-autotest-1.s3.amazonaws.com/xyz/etc/logo.png'],
	must_find_re = [ 'logo.png.*saved \[22059/22059\]' ])

test_s3cmd("Sync more to S3", ['sync', 'testsuite', 's3://s3cmd-autotest-1/xyz/', '--exclude', '*.png', '--no-encrypt'])

test_s3cmd("Rename within S3", ['mv', 's3://s3cmd-autotest-1/xyz/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	must_find = [ 'Object s3://s3cmd-autotest-1/xyz/etc/logo.png moved to s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG' ])

test_s3cmd("Rename (NoSuchKey)", ['mv', 's3://s3cmd-autotest-1/xyz/etc/logo.png', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	retcode = 1,
	must_find_re = [ 'ERROR:.*NoSuchKey' ],
	must_not_find = [ 'Object s3://s3cmd-autotest-1/xyz/etc/logo.png moved to s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG' ])

test_s3cmd("Sync more from S3", ['sync', '--delete-removed', 's3://s3cmd-autotest-1/xyz', 'testsuite-out'],
	must_find = [ "deleted 'testsuite-out/etc/logo.png'", "stored as testsuite-out/etc2/Logo.PNG (22059 bytes", 
	              "stored as testsuite-out/.svn/format " ],
	must_not_find = [ "not-deleted etc/logo.png" ])

test_s3cmd("Copy between buckets", ['cp', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG', 's3://s3cmd-Autotest-3'],
	must_find = [ "Object s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG copied to s3://s3cmd-Autotest-3/xyz/etc2/Logo.PNG" ])

test_s3cmd("Simple delete", ['del', 's3://s3cmd-autotest-1/xyz/etc2/Logo.PNG'],
	must_find = [ "Object s3://s3cmd-autotest-1/xyz/etc2/Logo.PNG deleted" ])

test_s3cmd("Recursive delete", ['del', '--recursive', 's3://s3cmd-autotest-1/xyz/unicode'],
	must_find_re = [ "Object.*unicode/ŪņЇЌœđЗ/.*deleted" ])

test_s3cmd("Recursive delete all", ['del', '--recursive', '--force', 's3://s3cmd-autotest-1'],
	must_find_re = [ "Object.*binary/random-crap deleted" ])

test_s3cmd("Remove empty bucket", ['rb', 's3://s3cmd-autotest-1'],
	must_find = [ "Bucket 's3://s3cmd-autotest-1/' removed" ])

test_s3cmd("Remove remaining buckets", ['rb', '--recursive', 's3://s3cmd-autotest-2', 's3://s3cmd-Autotest-3'],
	must_find = [ "Bucket 's3://s3cmd-autotest-2/' removed",
		      "Bucket 's3://s3cmd-Autotest-3/' removed" ])
