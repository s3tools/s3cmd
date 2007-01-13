from distutils.core import setup
setup(name = "s3cmd",
	version = "0.9.0a1",
	author = "Michal Ludvig",
	author_email = "michal@logix.cz",
	packages = [ 'S3' ],
	scripts = ['s3cmd'],
	)
