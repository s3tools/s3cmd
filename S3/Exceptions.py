## Amazon S3 manager - Exceptions library
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

from Utils import getRootTagName, unicodise, deunicodise
from logging import debug, info, warning, error

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

class S3Exception(Exception):
	def __init__(self, message = ""):
		self.message = unicodise(message)

	def __str__(self):
		return deunicodise(self.message)

	def __unicode__(self):
		return self.message

class S3Error (S3Exception):
	def __init__(self, response):
		self.status = response["status"]
		self.reason = response["reason"]
		self.info = {}
		debug("S3Error: %s (%s)" % (self.status, self.reason))
		if response.has_key("headers"):
			for header in response["headers"]:
				debug("HttpHeader: %s: %s" % (header, response["headers"][header]))
		if response.has_key("data") and getRootTagName(response["data"]) == "Error":
			tree = ET.fromstring(response["data"])
			for child in tree.getchildren():
				if child.text != "":
					debug("ErrorXML: " + child.tag + ": " + repr(child.text))
					self.info[child.tag] = child.text

	def __unicode__(self):
		retval = "%d (%s)" % (self.status, self.reason)
		try:
			retval += (": %s" % self.info["Code"])
		except (AttributeError, KeyError):
			pass
		return retval

class S3UploadError(S3Exception):
	pass

class S3DownloadError(S3Exception):
	pass

class S3RequestError(S3Exception):
	pass

class InvalidFileError(S3Exception):
	pass

class ParameterError(S3Exception):
	pass
