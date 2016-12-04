#!/usr/bin/env python2
# -*- coding=utf-8 -*-

## Amazon S3cmd - testsuite
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import print_function, unicode_literals

import imp
import locale
import re
import unittest

from StringIO import StringIO

import boto
import mock

from moto import mock_s3

s3cmd = imp.load_source('s3cmd', 's3cmd')

from S3.ExitCodes import *
from S3.Exceptions import *

bucket_prefix = 's3cmd-test-'


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


class S3CMDTest(unittest.TestCase):
    '''
    Test various s3cmd commands.

    '''

    def setUp(self):
        self.encoding = locale.getpreferredencoding()
        if not self.encoding:
            self.fail(
                'Guessing current system encoding failed. Consider setting $LANG variable.')
        else:
            print('System encoding: ' + self.encoding)

    @mock.patch('sys.stdout', new_callable=StringIO)
    def s3cmd_test(self,
                   cmd_args,
                   mock_stdout,
                   retcode=0,
                   must_find=None,
                   must_not_find=None,
                   must_find_re=None,
                   must_not_find_re=None,
                   stdin=None):
        if must_find is None:
            must_find = []
        if must_not_find is None:
            must_not_find = []
        if must_find_re is None:
            must_find_re = []
        if must_not_find_re is None:
            must_not_find_re = []

        if type(must_find) not in [list, tuple]:
            must_find = [must_find]
        if type(must_find_re) not in [list, tuple]:
            must_find_re = [must_find_re]
        if type(must_not_find) not in [list, tuple]:
            must_not_find = [must_not_find]
        if type(must_not_find_re) not in [list, tuple]:
            must_not_find_re = [must_not_find_re]

        if type(retcode) not in [list, tuple]:
            retcode = [retcode]

        def compile_list(_list, regexps=False):
            if regexps == False:
                _list = [re.escape(item.encode(self.encoding, 'replace'))
                         for item in _list]

            return [re.compile(item, re.MULTILINE) for item in _list]

        ret = s3cmd.main(cmd_args)
        self.assertIn(ret, retcode)

        find_list = []
        find_list.extend(compile_list(must_find))
        find_list.extend(compile_list(must_find_re, regexps=True))
        find_list_patterns = []
        find_list_patterns.extend(must_find)
        find_list_patterns.extend(must_find_re)

        not_find_list = []
        not_find_list.extend(compile_list(must_not_find))
        not_find_list.extend(compile_list(must_not_find_re, regexps=True))
        not_find_list_patterns = []
        not_find_list_patterns.extend(must_not_find)
        not_find_list_patterns.extend(must_not_find_re)

        stdout = mock_stdout.getvalue()

        for index in range(len(find_list)):
            match = find_list[index].search(stdout)
            if not match:
                self.fail('pattern not found: %s' % find_list_patterns[index])
        for index in range(len(not_find_list)):
            match = not_find_list[index].search(stdout)
            if match:
                self.fail('pattern found: %s (match: %s)' %
                          (not_find_list_patterns[index], match.group(0)))

    @mock_s3
    def test_remove_bucket(self):
        '''Are buckets removed correctly?'''

        conn = boto.connect_s3()
        for i in range(1, 3):
            conn.create_bucket(bucket(i))
        s3cmd.main(['rb', '-r', '--force', pbucket(1), pbucket(2)])

        for i in range(1, 3):
            self.assertIsNone(conn.lookup(bucket(i)))

    @mock_s3
    def test_create_bucket(self):
        '''Are buckets created correctly?'''
        conn = boto.connect_s3()

        s3cmd.main(['mb', '--bucket-location=EU', pbucket(1)])

        self.assertIsNotNone(conn.lookup(bucket(1)))

        s3cmd.main(['mb', '--bucket-location=EU', pbucket(2), pbucket(4)])

        self.assertIsNotNone(conn.lookup(bucket(2)))
        self.assertIsNotNone(conn.lookup(bucket(4)))

    @mock_s3
    def test_invalid_bucket_name(self):
        '''Are invalid bucket names checked?'''
        self.assertRaisesRegexp(
            ParameterError, r"Bucket name '.*' contains disallowed character",
            s3cmd.main, ['mb', '--bucket-location=EU', pbucket('EU')])

    @mock_s3
    def test_list_bucket(self):
        '''Are buckets listed correctly?'''
        conn = boto.connect_s3()
        for i in range(1, 3):
            conn.create_bucket(bucket(i))
        self.s3cmd_test(['ls'],
                        must_find=['autotest-1', 'autotest-2'],
                        must_not_find_re='autotest-EU')


if __name__ == '__main__':
    unittest.main()

# vim:et:ts=4:sts=4:ai
