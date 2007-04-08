from distutils.core import setup
import os

import S3.PkgInfo

## Remove 'MANIFEST' file to force
## distutils to recreate it
try:
	os.unlink("MANIFEST")
except:
	pass

## Compress manpage. It behaves weird 
## with bdist_rpm when not compressed.
os.system("gzip s3cmd.1")

## Main distutils info
setup(
	## Content description
	name = S3.PkgInfo.package,
	version = S3.PkgInfo.version,
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	data_files = [
		("share/doc/packages/s3cmd", [ "README", "INSTALL", "NEWS" ]),
		("share/man/man1", [ "s3cmd.1.gz" ] ),
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
