#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os

try:
    import xml.etree.ElementTree
    print("Using xml.etree.ElementTree for XML processing")
except ImportError as e:
    sys.stderr.write(str(e) + "\n")
    try:
        import elementtree.ElementTree
        print("Using elementtree.ElementTree for XML processing")
    except ImportError as e:
        sys.stderr.write(str(e) + "\n")
        sys.stderr.write("Please install ElementTree module from\n")
        sys.stderr.write("http://effbot.org/zone/element-index.htm\n")
        sys.exit(1)

from setuptools import setup

import S3.PkgInfo

if float("%d.%d" % sys.version_info[:2]) < 2.6:
    sys.stderr.write("Your Python version %d.%d.%d is not supported.\n" % sys.version_info[:3])
    sys.stderr.write("S3cmd requires Python 2.6 or newer.\n")
    sys.exit(1)

## Remove 'MANIFEST' file to force
## distutils to recreate it.
## Only in "sdist" stage. Otherwise
## it makes life difficult to packagers.
if len(sys.argv) > 1 and sys.argv[1] == "sdist":
    try:
        os.unlink("MANIFEST")
    except OSError as e:
        pass

## Re-create the manpage
## (Beware! Perl script on the loose!!)
if len(sys.argv) > 1 and sys.argv[1] == "sdist":
    if os.stat_result(os.stat("s3cmd.1")).st_mtime \
       < os.stat_result(os.stat("s3cmd")).st_mtime:
        sys.stderr.write("Re-create man page first!\n")
        sys.stderr.write("Run: ./s3cmd --help | ./format-manpage.pl > s3cmd.1\n")
        sys.exit(1)

## Don't install manpages and docs when $S3CMD_PACKAGING is set
## This was a requirement of Debian package maintainer.
if not os.getenv("S3CMD_PACKAGING"):
    man_path = os.getenv("S3CMD_INSTPATH_MAN") or "share/man"
    doc_path = os.getenv("S3CMD_INSTPATH_DOC") or "share/doc/packages"
    data_files = [
        (doc_path+"/s3cmd", ["README.md", "INSTALL.md", "LICENSE", "NEWS"]),
        (man_path+"/man1", ["s3cmd.1"]),
    ]
else:
    data_files = None

## Main distutils info
setup(
    ## Content description
    name=S3.PkgInfo.package,
    version=S3.PkgInfo.version,
    packages=['S3'],
    scripts=['s3cmd'],
    data_files=data_files,
    test_suite='S3.PkgInfo',

    ## Packaging details
    author="Michal Ludvig",
    author_email="michal@logix.cz",
    maintainer="github.com/fviard, github.com/matteobar",
    maintainer_email="s3tools-bugs@lists.sourceforge.net",
    url=S3.PkgInfo.url,
    license=S3.PkgInfo.license,
    description=S3.PkgInfo.short_description,
    long_description="""
%s

Authors:
--------
    Florent Viard <florent@sodria.com>

    Michal Ludvig  <michal@logix.cz>

    Matt Domsch (github.com/mdomsch)
""" % (S3.PkgInfo.long_description),

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: MacOS X',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: OS Independent',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Archiving',
        'Topic :: Utilities',
    ],

    install_requires=["python-dateutil", "python-magic"]
)

# vim:et:ts=4:sts=4:ai
