## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import re
import sys
from BidirMap import BidirMap

class S3Uri(object):
	type = None
	_subclasses = None

	def __new__(self, string):
		if not self._subclasses:
			## Generate a list of all subclasses of S3Uri
			self._subclasses = []
			dict = sys.modules[__name__].__dict__
			for something in dict:
				if type(dict[something]) is not type(self):
					continue
				if issubclass(dict[something], self) and dict[something] != self:
					self._subclasses.append(dict[something])
		for subclass in self._subclasses:
			try:
				instance = object.__new__(subclass)
				instance.__init__(string)
				return instance
			except ValueError, e:
				continue
		raise ValueError("%s: not a recognized URI" % string)
	
	def __str__(self):
		return self.uri()
	
class S3UriS3(S3Uri):
	type = "s3"
	_re = re.compile("^s3://([^/]+)/?(.*)", re.IGNORECASE)
	def __init__(self, string):
		match = self._re.match(string)
		if not match:
			raise ValueError("%s: not a S3 URI" % string)
		groups = match.groups()
		self._bucket = groups[0]
		self._object = groups[1]

	def bucket(self):
		return self._bucket

	def object(self):
		return self._object
	
	def has_bucket(self):
		return bool(self._bucket)

	def has_object(self):
		return bool(self._object)

	def uri(self):
		return "/".join(["s3:/", self._bucket, self._object])
	
	@staticmethod
	def compose_uri(bucket, object = ""):
		return "s3://%s/%s" % (bucket, object)

class S3UriS3FS(S3Uri):
	type = "s3fs"
	_re = re.compile("^s3fs://([^/]*)/?(.*)", re.IGNORECASE)
	def __init__(self, string):
		match = self._re.match(string)
		if not match:
			raise ValueError("%s: not a S3fs URI" % string)
		groups = match.groups()
		self._fsname = groups[0]
		self._path = groups[1].split("/")

	def fsname(self):
		return self._fsname

	def path(self):
		return "/".join(self._path)

	def uri(self):
		return "/".join(["s3fs:/", self._fsname, self.path()])

class S3UriFile(S3Uri):
	type = "file"
	_re = re.compile("^(\w+://)?(.*)")
	def __init__(self, string):
		match = self._re.match(string)
		groups = match.groups()
		if groups[0] not in (None, "file://"):
			raise ValueError("%s: not a file:// URI" % string)
		self._path = groups[1].split("/")

	def path(self):
		return "/".join(self._path)

	def uri(self):
		return "/".join(["file:/", self.path()])

if __name__ == "__main__":
	uri = S3Uri("s3://bucket/object")
	print "type()  =", type(uri)
	print "uri     =", uri
	print "uri.type=", uri.type
	print "bucket  =", uri.bucket()
	print "object  =", uri.object()
	print

	uri = S3Uri("s3://bucket")
	print "type()  =", type(uri)
	print "uri     =", uri
	print "uri.type=", uri.type
	print "bucket  =", uri.bucket()
	print

	uri = S3Uri("s3fs://filesystem1/path/to/remote/file.txt")
	print "type()  =", type(uri)
	print "uri     =", uri
	print "uri.type=", uri.type
	print "path    =", uri.path()
	print

	uri = S3Uri("/path/to/local/file.txt")
	print "type()  =", type(uri)
	print "uri     =", uri
	print "uri.type=", uri.type
	print "path    =", uri.path()
	print
