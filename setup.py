from distutils.core import setup
import os

try:
	os.unlink("MANIFEST")
except:
	pass

setup(name = "s3cmd",
	## Content description
	version = "0.9.1",
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	data_files = [ ("share/s3cmd", [ "README", "INSTALL", "NEWS" ]), ],

	## Packaging details
	author = "Michal Ludvig",
	author_email = "michal@logix.cz",
	url = 'http://s3tools.sourceforge.net',
	license = 'GPL version 2',
	description = 'S3cmd is a tool for managing your Amazon S3 storage.',
	long_description = """
S3cmd lets you copy files from/to Amazon S3 
(Simple Storage Service) using a simple to use
command line client.

Authors:
--------
    Michal Ludvig <michal@logix.cz>
""",
	)
