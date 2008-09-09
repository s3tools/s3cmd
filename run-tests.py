#!/usr/bin/env python

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
		print "FAIL%s" % (message)
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
		print "OK%s" % (message)
		count_pass += 1
		return 0
	def compile_list(_list, regexps = False):
		if type(_list) not in [ list, tuple ]:
			_list = [_list]

		if regexps == False:
			_list = [re.escape(item) for item in _list]

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
	not_find_list = []
	not_find_list.extend(compile_list(must_not_find))
	not_find_list.extend(compile_list(must_not_find_re, regexps = True))

	for pattern in find_list:
		match = pattern.search(stdout)
		if not match:
			return failure("pattern not found: %s" % match.group())
	for pattern in not_find_list:
		match = pattern.search(stdout)
		if match:
			return failure("pattern found: %s" % match.group())
	return success()

def test_s3cmd(label, cmd_args = [], **kwargs):
	if not cmd_args[0].endswith("s3cmd"):
		cmd_args.insert(0, "./s3cmd")
	return test(label, cmd_args, **kwargs)

test_s3cmd("Remove test buckets", ['rb', '-r', 's3://s3cmd-autotest-1', 's3://s3cmd-autotest-2', 's3://s3cmd-autotest-3'],
	must_find = [ "Bucket 's3://s3cmd-autotest-1/' removed",
		      "Bucket 's3://s3cmd-autotest-2/' removed",
		      "Bucket 's3://s3cmd-autotest-3/' removed" ])
	
test_s3cmd("Create one bucket", ['mb', 's3://s3cmd-autotest-1'], 
	must_find = "Bucket 's3://s3cmd-autotest-1/' created")

test_s3cmd("Create multiple buckets", ['mb', 's3://s3cmd-autotest-2', 's3://s3cmd-autotest-3'], 
	must_find = [ "Bucket 's3://s3cmd-autotest-2/' created", "Bucket 's3://s3cmd-autotest-3/' created" ])

test_s3cmd("Invalid bucket name", ["mb", "s3://s3cmd-Autotest-.-"], 
	retcode = 1,
	must_find = "ERROR: Parameter problem: Bucket name", 
	must_not_find_re = "Bucket.*created")

test_s3cmd("Buckets list", ["ls"], 
	must_find = [ "autotest-1", "autotest-2", "autotest-3" ], must_not_find_re = "Autotest")

test_s3cmd("Sync with exclude", ['sync', 'testsuite', 's3://s3cmd-autotest-1/xyz/', '--exclude', '*/thousands/*', '--no-encrypt'])
