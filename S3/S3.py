## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import sys
import os, os.path
import time
import httplib
import logging
import mimetypes
import re
from logging import debug, info, warning, error
from stat import ST_SIZE

try:
	from hashlib import md5
except ImportError:
	from md5 import md5

from Utils import *
from SortedDict import SortedDict
from BidirMap import BidirMap
from Config import Config
from Exceptions import *
from ACL import ACL, GranteeLogDelivery
from AccessLog import AccessLog
from S3Uri import S3Uri

__all__ = []
class S3Request(object):
	def __init__(self, s3, method_string, resource, headers, params = {}):
		self.s3 = s3
		self.headers = SortedDict(headers or {}, ignore_case = True)
		self.resource = resource
		self.method_string = method_string
		self.params = params

		self.update_timestamp()
		self.sign()

	def update_timestamp(self):
		if self.headers.has_key("date"):
			del(self.headers["date"])
		self.headers["x-amz-date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

	def format_param_str(self):
		"""
		Format URL parameters from self.params and returns
		?parm1=val1&parm2=val2 or an empty string if there 
		are no parameters.  Output of this function should 
		be appended directly to self.resource['uri']
		"""
		param_str = ""
		for param in self.params:
			if self.params[param] not in (None, ""):
				param_str += "&%s=%s" % (param, self.params[param])
			else:
				param_str += "&%s" % param
		return param_str and "?" + param_str[1:]

	def sign(self):
		h  = self.method_string + "\n"
		h += self.headers.get("content-md5", "")+"\n"
		h += self.headers.get("content-type", "")+"\n"
		h += self.headers.get("date", "")+"\n"
		for header in self.headers.keys():
			if header.startswith("x-amz-"):
				h += header+":"+str(self.headers[header])+"\n"
		if self.resource['bucket']:
			h += "/" + self.resource['bucket']
		h += self.resource['uri']
		debug("SignHeaders: " + repr(h))
		signature = sign_string(h)

		self.headers["Authorization"] = "AWS "+self.s3.config.access_key+":"+signature

	def get_triplet(self):
		self.update_timestamp()
		self.sign()
		resource = dict(self.resource)	## take a copy
		resource['uri'] += self.format_param_str()
		return (self.method_string, resource, self.headers)

class S3(object):
	http_methods = BidirMap(
		GET = 0x01,
		PUT = 0x02,
		HEAD = 0x04,
		DELETE = 0x08,
		MASK = 0x0F,
		)
	
	targets = BidirMap(
		SERVICE = 0x0100,
		BUCKET = 0x0200,
		OBJECT = 0x0400,
		MASK = 0x0700,
		)

	operations = BidirMap(
		UNDFINED = 0x0000,
		LIST_ALL_BUCKETS = targets["SERVICE"] | http_methods["GET"],
		BUCKET_CREATE = targets["BUCKET"] | http_methods["PUT"],
		BUCKET_LIST = targets["BUCKET"] | http_methods["GET"],
		BUCKET_DELETE = targets["BUCKET"] | http_methods["DELETE"],
		OBJECT_PUT = targets["OBJECT"] | http_methods["PUT"],
		OBJECT_GET = targets["OBJECT"] | http_methods["GET"],
		OBJECT_HEAD = targets["OBJECT"] | http_methods["HEAD"],
		OBJECT_DELETE = targets["OBJECT"] | http_methods["DELETE"],
	)

	codes = {
		"NoSuchBucket" : "Bucket '%s' does not exist",
		"AccessDenied" : "Access to bucket '%s' was denied",
		"BucketAlreadyExists" : "Bucket '%s' already exists",
		}

	## S3 sometimes sends HTTP-307 response 
	redir_map = {}

	## Maximum attempts of re-issuing failed requests
	_max_retries = 5

	def __init__(self, config):
		self.config = config

	def get_connection(self, bucket):
		if self.config.proxy_host != "":
			return httplib.HTTPConnection(self.config.proxy_host, self.config.proxy_port)
		else:
			if self.config.use_https:
				return httplib.HTTPSConnection(self.get_hostname(bucket))
			else:
				return httplib.HTTPConnection(self.get_hostname(bucket))

	def get_hostname(self, bucket):
		if bucket and check_bucket_name_dns_conformity(bucket):
			if self.redir_map.has_key(bucket):
				host = self.redir_map[bucket]
			else:
				host = getHostnameFromBucket(bucket)
		else:
			host = self.config.host_base
		debug('get_hostname(%s): %s' % (bucket, host))
		return host

	def set_hostname(self, bucket, redir_hostname):
		self.redir_map[bucket] = redir_hostname

	def format_uri(self, resource):
		if resource['bucket'] and not check_bucket_name_dns_conformity(resource['bucket']):
			uri = "/%s%s" % (resource['bucket'], resource['uri'])
		else:
			uri = resource['uri']
		if self.config.proxy_host != "":
			uri = "http://%s%s" % (self.get_hostname(resource['bucket']), uri)
		debug('format_uri(): ' + uri)
		return uri

	## Commands / Actions
	def list_all_buckets(self):
		request = self.create_request("LIST_ALL_BUCKETS")
		response = self.send_request(request)
		response["list"] = getListFromXml(response["data"], "Bucket")
		return response
	
	def bucket_list(self, bucket, prefix = None, recursive = None):
		def _list_truncated(data):
			## <IsTruncated> can either be "true" or "false" or be missing completely
			is_truncated = getTextFromXml(data, ".//IsTruncated") or "false"
			return is_truncated.lower() != "false"

		def _get_contents(data):
			return getListFromXml(data, "Contents")

		def _get_common_prefixes(data):
			return getListFromXml(data, "CommonPrefixes")

		uri_params = {}
		truncated = True
		list = []
		prefixes = []

		while truncated:
			response = self.bucket_list_noparse(bucket, prefix, recursive, uri_params)
			current_list = _get_contents(response["data"])
			current_prefixes = _get_common_prefixes(response["data"])
			truncated = _list_truncated(response["data"])
			if truncated:
				if current_list:
					uri_params['marker'] = self.urlencode_string(current_list[-1]["Key"])
				else:
					uri_params['marker'] = self.urlencode_string(current_prefixes[-1]["Prefix"])
				debug("Listing continues after '%s'" % uri_params['marker'])

			list += current_list
			prefixes += current_prefixes

		response['list'] = list
		response['common_prefixes'] = prefixes
		return response

	def bucket_list_noparse(self, bucket, prefix = None, recursive = None, uri_params = {}):
		if prefix:
			uri_params['prefix'] = self.urlencode_string(prefix)
		if not self.config.recursive and not recursive:
			uri_params['delimiter'] = "/"
		request = self.create_request("BUCKET_LIST", bucket = bucket, **uri_params)
		response = self.send_request(request)
		#debug(response)
		return response

	def bucket_create(self, bucket, bucket_location = None):
		headers = SortedDict(ignore_case = True)
		body = ""
		if bucket_location and bucket_location.strip().upper() != "US":
			bucket_location = bucket_location.strip()
			if bucket_location.upper() == "EU":
				bucket_location = bucket_location.upper()
			else:
				bucket_location = bucket_location.lower()
			body  = "<CreateBucketConfiguration><LocationConstraint>"
			body += bucket_location
			body += "</LocationConstraint></CreateBucketConfiguration>"
			debug("bucket_location: " + body)
			check_bucket_name(bucket, dns_strict = True)
		else:
			check_bucket_name(bucket, dns_strict = False)
		if self.config.acl_public:
			headers["x-amz-acl"] = "public-read"
		request = self.create_request("BUCKET_CREATE", bucket = bucket, headers = headers)
		response = self.send_request(request, body)
		return response

	def bucket_delete(self, bucket):
		request = self.create_request("BUCKET_DELETE", bucket = bucket)
		response = self.send_request(request)
		return response

	def bucket_info(self, uri):
		request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?location")
		response = self.send_request(request)
		response['bucket-location'] = getTextFromXml(response['data'], "LocationConstraint") or "any"
		return response

	def object_put(self, filename, uri, extra_headers = None, extra_label = ""):
		# TODO TODO
		# Make it consistent with stream-oriented object_get()
		if uri.type != "s3":
			raise ValueError("Expected URI type 's3', got '%s'" % uri.type)

		if not os.path.isfile(filename):
			raise InvalidFileError(u"%s is not a regular file" % unicodise(filename))
		try:
			file = open(filename, "rb")
			size = os.stat(filename)[ST_SIZE]
		except (IOError, OSError), e:
			raise InvalidFileError(u"%s: %s" % (unicodise(filename), e.strerror))
		headers = SortedDict(ignore_case = True)
		if extra_headers:
			headers.update(extra_headers)
		headers["content-length"] = size
		content_type = None
		if self.config.guess_mime_type:
			content_type = mimetypes.guess_type(filename)[0]
		if not content_type:
			content_type = self.config.default_mime_type
		debug("Content-Type set to '%s'" % content_type)
		headers["content-type"] = content_type
		if self.config.acl_public:
			headers["x-amz-acl"] = "public-read"
		if self.config.reduced_redundancy:
			headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY"
		request = self.create_request("OBJECT_PUT", uri = uri, headers = headers)
		labels = { 'source' : unicodise(filename), 'destination' : unicodise(uri.uri()), 'extra' : extra_label }
		response = self.send_file(request, file, labels)
		return response

	def object_get(self, uri, stream, start_position = 0, extra_label = ""):
		if uri.type != "s3":
			raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
		request = self.create_request("OBJECT_GET", uri = uri)
		labels = { 'source' : unicodise(uri.uri()), 'destination' : unicodise(stream.name), 'extra' : extra_label }
		response = self.recv_file(request, stream, labels, start_position)
		return response

	def object_delete(self, uri):
		if uri.type != "s3":
			raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
		request = self.create_request("OBJECT_DELETE", uri = uri)
		response = self.send_request(request)
		return response

	def object_copy(self, src_uri, dst_uri, extra_headers = None):
		if src_uri.type != "s3":
			raise ValueError("Expected URI type 's3', got '%s'" % src_uri.type)
		if dst_uri.type != "s3":
			raise ValueError("Expected URI type 's3', got '%s'" % dst_uri.type)
		headers = SortedDict(ignore_case = True)
		headers['x-amz-copy-source'] = "/%s/%s" % (src_uri.bucket(), self.urlencode_string(src_uri.object()))
		## TODO: For now COPY, later maybe add a switch?
		headers['x-amz-metadata-directive'] = "COPY"
		if self.config.acl_public:
			headers["x-amz-acl"] = "public-read"
		if self.config.reduced_redundancy:
			headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY"
		# if extra_headers:
		# 	headers.update(extra_headers)
		request = self.create_request("OBJECT_PUT", uri = dst_uri, headers = headers)
		response = self.send_request(request)
		return response

	def object_move(self, src_uri, dst_uri, extra_headers = None):
		response_copy = self.object_copy(src_uri, dst_uri, extra_headers)
		debug("Object %s copied to %s" % (src_uri, dst_uri))
		if getRootTagName(response_copy["data"]) == "CopyObjectResult":
			response_delete = self.object_delete(src_uri)
			debug("Object %s deleted" % src_uri)
		return response_copy

	def object_info(self, uri):
		request = self.create_request("OBJECT_HEAD", uri = uri)
		response = self.send_request(request)
		return response

	def get_acl(self, uri):
		if uri.has_object():
			request = self.create_request("OBJECT_GET", uri = uri, extra = "?acl")
		else:
			request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?acl")

		response = self.send_request(request)
		acl = ACL(response['data'])
		return acl

	def set_acl(self, uri, acl):
		if uri.has_object():
			request = self.create_request("OBJECT_PUT", uri = uri, extra = "?acl")
		else:
			request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(), extra = "?acl")

		body = str(acl)
		debug(u"set_acl(%s): acl-xml: %s" % (uri, body))
		response = self.send_request(request, body)
		return response

	def get_accesslog(self, uri):
		request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?logging")
		response = self.send_request(request)
		accesslog = AccessLog(response['data'])
		return accesslog

	def set_accesslog_acl(self, uri):
		acl = self.get_acl(uri)
		debug("Current ACL(%s): %s" % (uri.uri(), str(acl)))
		acl.appendGrantee(GranteeLogDelivery("READ_ACP"))
		acl.appendGrantee(GranteeLogDelivery("WRITE"))
		debug("Updated ACL(%s): %s" % (uri.uri(), str(acl)))
		self.set_acl(uri, acl)

	def set_accesslog(self, uri, enable, log_target_prefix_uri = None, acl_public = False):
		request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(), extra = "?logging")
		accesslog = AccessLog()
		if enable:
			accesslog.enableLogging(log_target_prefix_uri)
			accesslog.setAclPublic(acl_public)
		else:
			accesslog.disableLogging()
		body = str(accesslog)
		debug(u"set_accesslog(%s): accesslog-xml: %s" % (uri, body))
		try:
			response = self.send_request(request, body)
		except S3Error, e:
			if e.info['Code'] == "InvalidTargetBucketForLogging":
				info("Setting up log-delivery ACL for target bucket.")
				self.set_accesslog_acl(S3Uri("s3://%s" % log_target_prefix_uri.bucket()))
				response = self.send_request(request, body)
			else:
				raise
		return accesslog, response

	## Low level methods
	def urlencode_string(self, string, urlencoding_mode = None):
		if type(string) == unicode:
			string = string.encode("utf-8")

		if urlencoding_mode is None:
			urlencoding_mode = self.config.urlencoding_mode

		if urlencoding_mode == "verbatim":
			## Don't do any pre-processing
			return string

		encoded = ""
		## List of characters that must be escaped for S3
		## Haven't found this in any official docs
		## but my tests show it's more less correct.
		## If you start getting InvalidSignature errors
		## from S3 check the error headers returned
		## from S3 to see whether the list hasn't
		## changed.
		for c in string:	# I'm not sure how to know in what encoding 
					# 'object' is. Apparently "type(object)==str"
					# but the contents is a string of unicode
					# bytes, e.g. '\xc4\x8d\xc5\xafr\xc3\xa1k'
					# Don't know what it will do on non-utf8 
					# systems.
					#           [hope that sounds reassuring ;-)]
			o = ord(c)
			if (o < 0x20 or o == 0x7f):
				if urlencoding_mode == "fixbucket":
					encoded += "%%%02X" % o
				else:
					error(u"Non-printable character 0x%02x in: %s" % (o, string))
					error(u"Please report it to s3tools-bugs@lists.sourceforge.net")
					encoded += replace_nonprintables(c)
			elif (o == 0x20 or	# Space and below
			    o == 0x22 or	# "
			    o == 0x23 or	# #
			    o == 0x25 or	# % (escape character)
			    o == 0x26 or	# &
			    o == 0x2B or	# + (or it would become <space>)
			    o == 0x3C or	# <
			    o == 0x3E or	# >
			    o == 0x3F or	# ?
			    o == 0x60 or	# `
			    o >= 123):   	# { and above, including >= 128 for UTF-8
				encoded += "%%%02X" % o
			else:
				encoded += c
		debug("String '%s' encoded to '%s'" % (string, encoded))
		return encoded

	def create_request(self, operation, uri = None, bucket = None, object = None, headers = None, extra = None, **params):
		resource = { 'bucket' : None, 'uri' : "/" }

		if uri and (bucket or object):
			raise ValueError("Both 'uri' and either 'bucket' or 'object' parameters supplied")
		## If URI is given use that instead of bucket/object parameters
		if uri:
			bucket = uri.bucket()
			object = uri.has_object() and uri.object() or None

		if bucket:
			resource['bucket'] = str(bucket)
			if object:
				resource['uri'] = "/" + self.urlencode_string(object)
		if extra:
			resource['uri'] += extra

		method_string = S3.http_methods.getkey(S3.operations[operation] & S3.http_methods["MASK"])

		request = S3Request(self, method_string, resource, headers, params)

		debug("CreateRequest: resource[uri]=" + resource['uri'])
		return request
	
	def _fail_wait(self, retries):
		# Wait a few seconds. The more it fails the more we wait.
		return (self._max_retries - retries + 1) * 3
		
	def send_request(self, request, body = None, retries = _max_retries):
		method_string, resource, headers = request.get_triplet()
		debug("Processing request, please wait...")
		if not headers.has_key('content-length'):
			headers['content-length'] = body and len(body) or 0
		try:
			# "Stringify" all headers
			for header in headers.keys():
				headers[header] = str(headers[header])
			conn = self.get_connection(resource['bucket'])
			conn.request(method_string, self.format_uri(resource), body, headers)
			response = {}
			http_response = conn.getresponse()
			response["status"] = http_response.status
			response["reason"] = http_response.reason
			response["headers"] = convertTupleListToDict(http_response.getheaders())
			response["data"] =  http_response.read()
			debug("Response: " + str(response))
			conn.close()
		except Exception, e:
			if retries:
				warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				return self.send_request(request, body, retries - 1)
			else:
				raise S3RequestError("Request failed for: %s" % resource['uri'])

		if response["status"] == 307:
			## RedirectPermanent
			redir_bucket = getTextFromXml(response['data'], ".//Bucket")
			redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
			self.set_hostname(redir_bucket, redir_hostname)
			warning("Redirected to: %s" % (redir_hostname))
			return self.send_request(request, body)

		if response["status"] >= 500:
			e = S3Error(response)
			if retries:
				warning(u"Retrying failed request: %s" % resource['uri'])
				warning(unicode(e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				return self.send_request(request, body, retries - 1)
			else:
				raise e

		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)

		return response

	def send_file(self, request, file, labels, throttle = 0, retries = _max_retries):
		method_string, resource, headers = request.get_triplet()
		size_left = size_total = headers.get("content-length")
		if self.config.progress_meter:
			progress = self.config.progress_class(labels, size_total)
		else:
			info("Sending file '%s', please wait..." % file.name)
		timestamp_start = time.time()
		try:
			conn = self.get_connection(resource['bucket'])
			conn.connect()
			conn.putrequest(method_string, self.format_uri(resource))
			for header in headers.keys():
				conn.putheader(header, str(headers[header]))
			conn.endheaders()
		except Exception, e:
			if self.config.progress_meter:
				progress.done("failed")
			if retries:
				warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				# Connection error -> same throttle value
				return self.send_file(request, file, labels, throttle, retries - 1)
			else:
				raise S3UploadError("Upload failed for: %s" % resource['uri'])
		file.seek(0)
		md5_hash = md5()
		try:
			while (size_left > 0):
				#debug("SendFile: Reading up to %d bytes from '%s'" % (self.config.send_chunk, file.name))
				data = file.read(self.config.send_chunk)
				md5_hash.update(data)
				conn.send(data)
				if self.config.progress_meter:
					progress.update(delta_position = len(data))
				size_left -= len(data)
				if throttle:
					time.sleep(throttle)
			md5_computed = md5_hash.hexdigest()
			response = {}
			http_response = conn.getresponse()
			response["status"] = http_response.status
			response["reason"] = http_response.reason
			response["headers"] = convertTupleListToDict(http_response.getheaders())
			response["data"] = http_response.read()
			response["size"] = size_total
			conn.close()
			debug(u"Response: %s" % response)
		except Exception, e:
			if self.config.progress_meter:
				progress.done("failed")
			if retries:
				if retries < self._max_retries:
					throttle = throttle and throttle * 5 or 0.01
				warning("Upload failed: %s (%s)" % (resource['uri'], e))
				warning("Retrying on lower speed (throttle=%0.2f)" % throttle)
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				# Connection error -> same throttle value
				return self.send_file(request, file, labels, throttle, retries - 1)
			else:
				debug("Giving up on '%s' %s" % (file.name, e))
				raise S3UploadError("Upload failed for: %s" % resource['uri'])

		timestamp_end = time.time()
		response["elapsed"] = timestamp_end - timestamp_start
		response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)

		if self.config.progress_meter:
			## The above conn.close() takes some time -> update() progress meter
			## to correct the average speed. Otherwise people will complain that 
			## 'progress' and response["speed"] are inconsistent ;-)
			progress.update()
			progress.done("done")

		if response["status"] == 307:
			## RedirectPermanent
			redir_bucket = getTextFromXml(response['data'], ".//Bucket")
			redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
			self.set_hostname(redir_bucket, redir_hostname)
			warning("Redirected to: %s" % (redir_hostname))
			return self.send_file(request, file, labels)

		# S3 from time to time doesn't send ETag back in a response :-(
		# Force re-upload here.
		if not response['headers'].has_key('etag'):
			response['headers']['etag'] = '' 

		if response["status"] < 200 or response["status"] > 299:
			try_retry = False
			if response["status"] >= 500:
				## AWS internal error - retry
				try_retry = True
			elif response["status"] >= 400:
				err = S3Error(response)
				## Retriable client error?
				if err.code in [ 'BadDigest', 'OperationAborted', 'TokenRefreshRequired', 'RequestTimeout' ]:
					try_retry = True

			if try_retry:
				if retries:
					warning("Upload failed: %s (%s)" % (resource['uri'], S3Error(response)))
					warning("Waiting %d sec..." % self._fail_wait(retries))
					time.sleep(self._fail_wait(retries))
					return self.send_file(request, file, labels, throttle, retries - 1)
				else:
					warning("Too many failures. Giving up on '%s'" % (file.name))
					raise S3UploadError

			## Non-recoverable error
			raise S3Error(response)

		debug("MD5 sums: computed=%s, received=%s" % (md5_computed, response["headers"]["etag"]))
		if response["headers"]["etag"].strip('"\'') != md5_hash.hexdigest():
			warning("MD5 Sums don't match!")
			if retries:
				warning("Retrying upload of %s" % (file.name))
				return self.send_file(request, file, labels, throttle, retries - 1)
			else:
				warning("Too many failures. Giving up on '%s'" % (file.name))
				raise S3UploadError

		return response

	def recv_file(self, request, stream, labels, start_position = 0, retries = _max_retries):
		method_string, resource, headers = request.get_triplet()
		if self.config.progress_meter:
			progress = self.config.progress_class(labels, 0)
		else:
			info("Receiving file '%s', please wait..." % stream.name)
		timestamp_start = time.time()
		try:
			conn = self.get_connection(resource['bucket'])
			conn.connect()
			conn.putrequest(method_string, self.format_uri(resource))
			for header in headers.keys():
				conn.putheader(header, str(headers[header]))
			if start_position > 0:
				debug("Requesting Range: %d .. end" % start_position)
				conn.putheader("Range", "bytes=%d-" % start_position)
			conn.endheaders()
			response = {}
			http_response = conn.getresponse()
			response["status"] = http_response.status
			response["reason"] = http_response.reason
			response["headers"] = convertTupleListToDict(http_response.getheaders())
			debug("Response: %s" % response)
		except Exception, e:
			if self.config.progress_meter:
				progress.done("failed")
			if retries:
				warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				# Connection error -> same throttle value
				return self.recv_file(request, stream, labels, start_position, retries - 1)
			else:
				raise S3DownloadError("Download failed for: %s" % resource['uri'])

		if response["status"] == 307:
			## RedirectPermanent
			response['data'] = http_response.read()
			redir_bucket = getTextFromXml(response['data'], ".//Bucket")
			redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
			self.set_hostname(redir_bucket, redir_hostname)
			warning("Redirected to: %s" % (redir_hostname))
			return self.recv_file(request, stream, labels)

		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)

		if start_position == 0:
			# Only compute MD5 on the fly if we're downloading from beginning
			# Otherwise we'd get a nonsense.
			md5_hash = md5()
		size_left = int(response["headers"]["content-length"])
		size_total = start_position + size_left
		current_position = start_position

		if self.config.progress_meter:
			progress.total_size = size_total
			progress.initial_position = current_position
			progress.current_position = current_position

		try:
			while (current_position < size_total):
				this_chunk = size_left > self.config.recv_chunk and self.config.recv_chunk or size_left
				data = http_response.read(this_chunk)
				stream.write(data)
				if start_position == 0:
					md5_hash.update(data)
				current_position += len(data)
				## Call progress meter from here...
				if self.config.progress_meter:
					progress.update(delta_position = len(data))
			conn.close()
		except Exception, e:
			if self.config.progress_meter:
				progress.done("failed")
			if retries:
				warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
				warning("Waiting %d sec..." % self._fail_wait(retries))
				time.sleep(self._fail_wait(retries))
				# Connection error -> same throttle value
				return self.recv_file(request, stream, labels, current_position, retries - 1)
			else:
				raise S3DownloadError("Download failed for: %s" % resource['uri'])

		stream.flush()
		timestamp_end = time.time()

		if self.config.progress_meter:
			## The above stream.flush() may take some time -> update() progress meter
			## to correct the average speed. Otherwise people will complain that 
			## 'progress' and response["speed"] are inconsistent ;-)
			progress.update()
			progress.done("done")

		if start_position == 0:
			# Only compute MD5 on the fly if we were downloading from the beginning
			response["md5"] = md5_hash.hexdigest()
		else:
			# Otherwise try to compute MD5 of the output file
			try:
				response["md5"] = hash_file_md5(stream.name)
			except IOError, e:
				if e.errno != errno.ENOENT:
					warning("Unable to open file: %s: %s" % (stream.name, e))
				warning("Unable to verify MD5. Assume it matches.")
				response["md5"] = response["headers"]["etag"]

		response["md5match"] = response["headers"]["etag"].find(response["md5"]) >= 0
		response["elapsed"] = timestamp_end - timestamp_start
		response["size"] = current_position
		response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)
		if response["size"] != start_position + long(response["headers"]["content-length"]):
			warning("Reported size (%s) does not match received size (%s)" % (
				start_position + response["headers"]["content-length"], response["size"]))
		debug("ReceiveFile: Computed MD5 = %s" % response["md5"])
		if not response["md5match"]:
			warning("MD5 signatures do not match: computed=%s, received=%s" % (
				response["md5"], response["headers"]["etag"]))
		return response
__all__.append("S3")
