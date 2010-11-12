from distutils.core import setup
import sys
import os

import S3.PkgInfo

if float("%d.%d" % sys.version_info[:2]) < 2.4:
	sys.stderr.write("Your Python version %d.%d.%d is not supported.\n" % sys.version_info[:3])
	sys.stderr.write("S3cmd requires Python 2.4 or newer.\n")
	sys.exit(1)

try:
	import xml.etree.ElementTree as ET
	print "Using xml.etree.ElementTree for XML processing"
except ImportError, e:
	sys.stderr.write(str(e) + "\n")
	try:
		import elementtree.ElementTree as ET
		print "Using elementtree.ElementTree for XML processing"
	except ImportError, e:
		sys.stderr.write(str(e) + "\n")
		sys.stderr.write("Please install ElementTree module from\n")
		sys.stderr.write("http://effbot.org/zone/element-index.htm\n")
		sys.exit(1)

try:
	## Remove 'MANIFEST' file to force
	## distutils to recreate it.
	## Only in "sdist" stage. Otherwise 
	## it makes life difficult to packagers.
	if sys.argv[1] == "sdist":
		os.unlink("MANIFEST")
except:
	pass

## Re-create the manpage
## (Beware! Perl script on the loose!!)
if sys.argv[1] == "sdist":
	if os.stat_result(os.stat("s3cmd.1")).st_mtime < os.stat_result(os.stat("s3cmd")).st_mtime:
		sys.stderr.write("Re-create man page first!\n")
		sys.stderr.write("Run: ./s3cmd --help | ./format-manpage.pl > s3cmd.1\n")
		sys.exit(1)

## Don't install manpages and docs when $S3CMD_PACKAGING is set
## This was a requirement of Debian package maintainer. 
if not os.getenv("S3CMD_PACKAGING"):
	man_path = os.getenv("S3CMD_INSTPATH_MAN") or "share/man"
	doc_path = os.getenv("S3CMD_INSTPATH_DOC") or "share/doc/packages"
	data_files = [	
		(doc_path+"/s3cmd", [ "README", "INSTALL", "NEWS" ]),
		(man_path+"/man1", [ "s3cmd.1" ] ),
	]
else:
	data_files = None

## Main distutils info
setup(
	## Content description
	name = S3.PkgInfo.package,
	version = S3.PkgInfo.version,
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	data_files = data_files,

	## Packaging details
	author = "Michal Ludvig",
	author_email = "michal@logix.cz",
	url = S3.PkgInfo.url,
	license = S3.PkgInfo.license,
	description = S3.PkgInfo.short_description,
	long_description = """
%s

Authors:
--------
    Michal Ludvig  <michal@logix.cz>
""" % (S3.PkgInfo.long_description)
	)
