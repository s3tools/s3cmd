## Amazon CloudFront support
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import base64
import time
import httplib
from logging import debug, info, warning, error

try:
	from hashlib import md5, sha1
except ImportError:
	from md5 import md5
	import sha as sha1
import hmac

from Config import Config
from Exceptions import *

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

class Distribution(object):
	pass

class CloudFront(object):
	operations = {
		"Create" : { 'method' : "PUT", 'resource' : "" },
		"Delete" : { 'method' : "DELETE", 'resource' : "/%(dist_id)s" },
		"GetList" : { 'method' : "GET", 'resource' : "" },
		"GetDistInfo" : { 'method' : "GET", 'resource' : "/%(dist_id)s" },
		"GetDistConfig" : { 'method' : "GET", 'resource' : "/%(dist_id)s/config" },
		"SetDistConfig" : { 'method' : "PUT", 'resource' : "/%(dist_id)s/config" },
	}

	## Maximum attempts of re-issuing failed requests
	_max_retries = 5

	def __init__(self, config):
		self.config = config

	## --------------------------------------------------
	## Methods implementing CloudFront API
	## --------------------------------------------------

	def GetList(self):
		response = self.send_request("GetList")
		return response

	## --------------------------------------------------
	## Low-level methods for handling CloudFront requests
	## --------------------------------------------------

	def send_request(self, op_name, dist_id = None, body = None, retries = _max_retries):
		operation = self.operations[op_name]
		request = self.create_request(operation, dist_id)
		conn = self.get_connection()
		conn.request(request['method'], request['resource'], body, request['headers'])
		http_response = conn.getresponse()
		response = {}
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = dict(http_response.getheaders())
		response["data"] =  http_response.read()
		conn.close()

		debug("CloudFront: response: %r" % response)

		if response["status"] >= 400:
			e = CloudFrontError(response)
			if retries:
				warning(u"Retrying failed request: %s" % op_name)
				warning(unicode(e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				return self.send_request(op_name, dist_id, body, retries - 1)
			else:
				raise e

		if response["status"] < 200 or response["status"] > 299:
			raise CloudFrontError(response)

		return response

	def create_request(self, operation, dist_id = None, headers = None):
		resource = self.config.cloudfront_resource + (
		           operation['resource'] % { 'dist_id' : dist_id })

		if not headers:
			headers = {}

		if headers.has_key("date"):
			if not headers.has_key("x-amz-date"):
				headers["x-amz-date"] = headers["date"]
			del(headers["date"])
		
		if not headers.has_key("x-amz-date"):
			headers["x-amz-date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

		signature = self.sign_request(headers)
		headers["Authorization"] = "AWS "+self.config.access_key+":"+signature

		request = {}
		request['resource'] = resource
		request['headers'] = headers
		request['method'] = operation['method']

		return request

	def sign_request(self, headers):
		string_to_sign = headers['x-amz-date']
		signature = base64.encodestring(hmac.new(self.config.secret_key, string_to_sign, sha1).digest()).strip()
		debug(u"CloudFront.sign_request('%s') = %s" % (string_to_sign, signature))
		return signature

	def get_connection(self):
		if self.config.proxy_host != "":
			raise ParameterError("CloudFront commands don't work from behind a HTTP proxy")
		return httplib.HTTPSConnection(self.config.cloudfront_host)

	def _fail_wait(self, retries):
		# Wait a few seconds. The more it fails the more we wait.
		return (self._max_retries - retries + 1) * 3

class Cmd(object):
	"""
	Class that implements CloudFront commands
	"""

	@staticmethod
	def list(args):
		cf = CloudFront(Config())
		response = cf.GetList()
