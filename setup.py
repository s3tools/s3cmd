from distutils.core import setup
import os

import S3.PkgInfo

try:
	os.unlink("MANIFEST")
except:
	pass

setup(
	## Content description
	name = S3.PkgInfo.package,
	version = S3.PkgInfo.version,
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	data_files = [ ("share/s3cmd", [ "README", "INSTALL", "NEWS" ]), ],

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
