from distutils.core import setup
import sys
import os

import S3.PkgInfo

try:
	## Remove 'MANIFEST' file to force
	## distutils to recreate it.
	## Only in "sdist" stage. Otherwise 
	## it makes life difficult to packagers.
	if sys.argv[1] == "sdist":
		os.unlink("MANIFEST")
except:
	pass

man_path = os.getenv("S3CMD_INSTPATH_MAN") or "share/man"
doc_path = os.getenv("S3CMD_INSTPATH_DOC") or "share/doc/packages"

## Main distutils info
setup(
	## Content description
	name = S3.PkgInfo.package,
	version = S3.PkgInfo.version,
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	data_files = [
		(doc_path+"/s3cmd", [ "README", "INSTALL", "NEWS" ]),
		(man_path+"/man1", [ "s3cmd.1" ] ),
	],

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
