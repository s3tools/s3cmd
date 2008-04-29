## Amazon SimpleDB library
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

"""
Low-level class for working with Amazon SimpleDB
"""

import time
import urllib
import base64
import hmac
import sha
import httplib
from logging import debug, info, warning, error

from Utils import convertTupleListToDict
from SortedDict import SortedDict
from Exceptions import *

class SimpleDB(object):
	# API Version
	# See http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/
	Version = "2007-11-07"
	SignatureVersion = 1

	def __init__(self, config):
		self.config = config

	def ListDomains(self, MaxNumberOfDomains = 100):
		'''
		Lists all domains associated with our Access Key. Returns 
		domain names up to the limit set by MaxNumberOfDomains.
		'''
		parameters = SortedDict()
		parameters['MaxNumberOfDomains'] = MaxNumberOfDomains
		response = self.send_request("ListDomains", domain = None, parameters = parameters)
		return response
	
	def send_request(self, *args, **kwargs):
		request = self.create_request(*args, **kwargs)
		debug("Request: %s" % repr(request))
		conn = self.get_connection()
		conn.request("GET", self.format_uri(request['uri_params']))
		http_response = conn.getresponse()
		response = {}
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = convertTupleListToDict(http_response.getheaders())
		response["data"] =  http_response.read()
		debug("Response: " + str(response))
		conn.close()

		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)

		return response

	def create_request(self, action, domain, parameters = None):
		if not parameters:
			parameters = SortedDict()
		parameters['AWSAccessKeyId'] = self.config.access_key
		parameters['Version'] = self.Version
		parameters['SignatureVersion'] = self.SignatureVersion
		parameters['Action'] = action
		parameters['Timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
		if domain:
			parameters['DomainName'] = domain
		parameters['Signature'] = self.sign_request(parameters)
		parameters.keys_return_lowercase = False
		uri_params = urllib.urlencode(parameters)
		request = {}
		request['uri_params'] = uri_params
		request['parameters'] = parameters
		return request

	def sign_request(self, parameters):
		h = ""
		parameters.keys_sort_lowercase = True
		parameters.keys_return_lowercase = False
		for key in parameters:
			h += "%s%s" % (key, parameters[key])
		debug("SignRequest: %s" % h)
		return base64.encodestring(hmac.new(self.config.secret_key, h, sha).digest()).strip()

	def get_connection(self):
		if self.config.proxy_host != "":
			return httplib.HTTPConnection(self.config.proxy_host, self.config.proxy_port)
		else:
			if self.config.use_https:
				return httplib.HTTPSConnection(self.config.simpledb_host)
			else:
				return httplib.HTTPConnection(self.config.simpledb_host)

	def format_uri(self, uri_params):
		if self.config.proxy_host != "":
			uri = "http://%s/?%s" % (self.config.simpledb_host, uri_params)
		else:
			uri = "/?%s" % uri_params
		debug('format_uri(): ' + uri)
		return uri
