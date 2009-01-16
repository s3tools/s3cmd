## Amazon CloudFront support
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import sys
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

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

from Config import Config
from Exceptions import *
from Utils import getTreeFromXml, appendXmlTextNode, getDictFromTree, dateS3toPython
from S3Uri import S3Uri

def output(message):
	sys.stdout.write(message + "\n")

def pretty_output(label, message):
	#label = ("%s " % label).ljust(20, ".")
	label = ("%s:" % label).ljust(15)
	output("%s %s" % (label, message))

class DistributionSummary(object):
	## Example:
	##
	## <DistributionSummary>
	##	<Id>1234567890ABC</Id>
	##	<Status>Deployed</Status>
	##	<LastModifiedTime>2009-01-16T11:49:02.189Z</LastModifiedTime>
	##	<DomainName>blahblahblah.cloudfront.net</DomainName>
	##	<Origin>example.bucket.s3.amazonaws.com</Origin>
	##	<Enabled>true</Enabled>
	## </DistributionSummary>
	
	def __init__(self, tree):
		if tree.tag != "DistributionSummary":
			raise ValueError("Expected <DistributionSummary /> xml, got: <%s />" % tree.tag)
		self.parse(tree)

	def parse(self, tree):
		self.info = getDictFromTree(tree)
		self.info['Enabled'] = (self.info['Enabled'].lower() == "true")

class DistributionList(object):
	## Example:
	## 
	## <DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2008-06-30/">
	##	<Marker />
	##	<MaxItems>100</MaxItems>
	##	<IsTruncated>false</IsTruncated>
	##	<DistributionSummary>
	##	... handled by DistributionSummary() class ...
	##	</DistributionSummary>
	## </DistributionList>

	def __init__(self, xml):
		tree = getTreeFromXml(xml)
		if tree.tag != "DistributionList":
			raise ValueError("Expected <DistributionList /> xml, got: <%s />" % tree.tag)
		self.parse(tree)

	def parse(self, tree):
		self.info = getDictFromTree(tree)
		## Normalise some items
		self.info['IsTruncated'] = (self.info['IsTruncated'].lower() == "true")

		self.dist_summs = []
		for dist_summ in tree.findall(".//DistributionSummary"):
			self.dist_summs.append(DistributionSummary(dist_summ))

class Distribution(object):
	## Example:
	##
	## <Distribution xmlns="http://cloudfront.amazonaws.com/doc/2008-06-30/">
	##	<Id>1234567890ABC</Id>
	##	<Status>InProgress</Status>
	##	<LastModifiedTime>2009-01-16T13:07:11.319Z</LastModifiedTime>
	##	<DomainName>blahblahblah.cloudfront.net</DomainName>
	##	<DistributionConfig>
	##	... handled by DistributionConfig() class ...
	##	</DistributionConfig>
	## </Distribution>

	def __init__(self, xml):
		tree = getTreeFromXml(xml)
		if tree.tag != "Distribution":
			raise ValueError("Expected <Distribution /> xml, got: <%s />" % tree.tag)
		self.parse(tree)

	def parse(self, tree):
		self.info = getDictFromTree(tree)
		## Normalise some items
		self.info['LastModifiedTime'] = dateS3toPython(self.info['LastModifiedTime'])

		self.info['DistributionConfig'] = DistributionConfig(tree = tree.find(".//DistributionConfig"))

class DistributionConfig(object):
	## Example:
	##
	## <DistributionConfig>
	##	<Origin>somebucket.s3.amazonaws.com</Origin>
	##	<CallerReference>s3://somebucket/</CallerReference>
	##	<Comment>http://somebucket.s3.amazonaws.com/</Comment>
	##	<Enabled>true</Enabled>
	## </DistributionConfig>

	EMPTY_CONFIG = "<DistributionConfig></DistributionConfig>"
	xmlns = "http://cloudfront.amazonaws.com/doc/2008-06-30/"
	def __init__(self, xml = None, tree = None):
		if not xml:
			xml = DistributionConfig.EMPTY_CONFIG

		if not tree:
			tree = getTreeFromXml(xml)

		if tree.tag != "DistributionConfig":
			raise ValueError("Expected <DistributionConfig /> xml, got: <%s />" % tree.tag)
		self.parse(tree)

	def parse(self, tree):
		self.Origin = tree.findtext(".//Origin") or ""
		self.CallerReference = tree.findtext(".//CallerReference") or ""
		self.Comment = tree.findtext(".//Comment") or ""
		self.Cnames = []
		for cname in tree.findall(".//CNAME"):
			self.Cnames.append(cname.text.lower())
		enabled = tree.findtext(".//Enabled") or ""
		self.Enabled = (enabled.lower() == "true")

	def __str__(self):
		tree = getTreeFromXml(DistributionConfig.EMPTY_CONFIG)
		tree.attrib['xmlns'] = DistributionConfig.xmlns

		## Retain the order of the following calls!
		appendXmlTextNode("Origin", self.Origin, tree)
		appendXmlTextNode("CallerReference", self.CallerReference, tree)
		if self.Comment:
			appendXmlTextNode("Comment", self.Comment, tree)
		for cname in self.Cnames:
			appendXmlTextNode("CNAME", cname.lower(), tree)
		appendXmlTextNode("Enabled", str(self.Enabled).lower(), tree)

		return ET.tostring(tree)

class CloudFront(object):
	operations = {
		"CreateDist" : { 'method' : "POST", 'resource' : "" },
		"DeleteDist" : { 'method' : "DELETE", 'resource' : "/%(dist_id)s" },
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
		response['dist_list'] = DistributionList(response['data'])
		if response['dist_list'].info['IsTruncated']:
			raise NotImplementedError("List is truncated. Ask s3cmd author to add support.")
		## TODO: handle Truncated 
		return response
	
	def CreateDistribution(self, uri, cnames = []):
		dist_conf = DistributionConfig()
		dist_conf.Enabled = True
		dist_conf.Origin = uri.host_name()
		dist_conf.CallerReference = str(uri)
		dist_conf.Comment = uri.public_url()
		if cnames:
			dist_conf.Cnames = cnames
		request_body = str(dist_conf)
		debug("CreateDistribution(): request_body: %s" % request_body)
		response = self.send_request("CreateDist", body = request_body)
		response['distribution'] = Distribution(response['data'])
		return response

	## --------------------------------------------------
	## Low-level methods for handling CloudFront requests
	## --------------------------------------------------

	def send_request(self, op_name, dist_id = None, body = None, retries = _max_retries):
		operation = self.operations[op_name]
		headers = {}
		if body:
			headers['content-type'] = 'text/plain'
		request = self.create_request(operation, dist_id, headers)
		conn = self.get_connection()
		debug("send_request(): %s %s" % (request['method'], request['resource']))
		conn.request(request['method'], request['resource'], body, request['headers'])
		http_response = conn.getresponse()
		response = {}
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = dict(http_response.getheaders())
		response["data"] =  http_response.read()
		conn.close()

		debug("CloudFront: response: %r" % response)

		if response["status"] >= 500:
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
		for d in response['dist_list'].dist_summs:
			pretty_output("Origin", d.info['Origin'])
			pretty_output("DomainName", d.info['DomainName'])
			pretty_output("Id", d.info['Id'])
			pretty_output("Status", d.info['Status'])
			pretty_output("Enabled", d.info['Enabled'])
			output("")
	
	@staticmethod
	def create(args):
		cf = CloudFront(Config())
		buckets = []
		for arg in args:
			uri = S3Uri(arg)
			if uri.type != "s3":
				raise ParameterError("Bucket can only be created from a s3:// URI instead of: %s" % arg)
			if uri.object():
				raise ParameterError("Use s3:// URI with a bucket name only instead of: %s" % arg)
			if not uri.is_dns_compatible():
				raise ParameterError("CloudFront can only handle lowercase-named buckets.")
			buckets.append(uri)
		if not buckets:
			raise ParameterError("No valid bucket names found")
		for uri in buckets:
			info("Creating distribution from: %s" % uri)
			response = cf.CreateDistribution(uri)
			d = response['distribution']
			dc = d.info['DistributionConfig']
			output("Distribution created:")
			#pretty_output("Origin", dc.info['Origin'])
			pretty_output("Origin", dc.Origin)
			pretty_output("DomainName", d.info['DomainName'])
			pretty_output("Id", d.info['Id'])
			pretty_output("Status", d.info['Status'])
			pretty_output("Enabled", dc.Enabled)
