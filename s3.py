#!/usr/bin/env python

import httplib2
import sys
import os, os.path
import logging
import time
import base64
import hmac
import hashlib
import httplib

from optparse import OptionParser
from logging import debug, info, warning, error
from stat import ST_SIZE
import elementtree.ElementTree as ET

## Our modules
from utils import *
from SortedDict import SortedDict
from BidirMap import BidirMap
from ConfigParser import ConfigParser

class AwsConfig:
	parsed_files = []
	access_key = ""
	secret_key = ""
	host = "s3.amazonaws.com"
	verbosity = logging.WARNING
	send_chunk = 4096
	recv_chunk = 4096
	human_readable_sizes = False
	force = False
	show_uri = False

	def __init__(self, configfile = None):
		if configfile:
			self.read_config_file(configfile)

	def read_config_file(self, configfile):
		cp = ConfigParser(configfile)
		AwsConfig.access_key = cp.get("access_key", AwsConfig.access_key)
		AwsConfig.secret_key = cp.get("secret_key", AwsConfig.secret_key)
		AwsConfig.host = cp.get("host", AwsConfig.host)
		verbosity = cp.get("verbosity", "WARNING")
		try:
			AwsConfig.verbosity = logging._levelNames[verbosity]
		except KeyError:
			error("AwsConfig: verbosity level '%s' is not valid" % verbosity)
		AwsConfig.parsed_files.append(configfile)

class S3Error (Exception):
	def __init__(self, response):
		self.status = response["status"]
		self.reason = response["reason"]
		debug("S3Error: %s (%s)" % (self.status, self.reason))
		if response.has_key("headers"):
			for header in response["headers"]:
				debug("HttpHeader: %s: %s" % (header, response["headers"][header]))
		if response.has_key("data"):
			tree = ET.fromstring(response["data"])
			for child in tree.getchildren():
				if child.text != "":
					debug("ErrorXML: " + child.tag + ": " + repr(child.text))
					self.__setattr__(child.tag, child.text)

	def __str__(self):
		retval = "%d (%s)" % (self.status, self.reason)
		try:
			retval += (": %s" % self.Code)
		except AttributeError:
			pass
		return retval

class ParameterError(Exception):
	pass

class S3:
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

	def __init__(self, config):
		self.config = config

	def list_all_buckets(self):
		request = self.create_request("LIST_ALL_BUCKETS")
		response = self.send_request(request)
		response["list"] = getListFromXml(response["data"], "Bucket")
		return response
	
	def bucket_list(self, bucket):
		request = self.create_request("BUCKET_LIST", bucket = bucket)
		response = self.send_request(request)
		response["list"] = getListFromXml(response["data"], "Contents")
		return response

	def bucket_create(self, bucket):
		self.check_bucket_name(bucket)
		request = self.create_request("BUCKET_CREATE", bucket = bucket)
		response = self.send_request(request)
		return response

	def bucket_delete(self, bucket):
		request = self.create_request("BUCKET_DELETE", bucket = bucket)
		response = self.send_request(request)
		return response

	def object_put(self, filename, bucket, object):
		if not os.path.isfile(filename):
			raise ParameterError("%s is not a regular file" % filename)
		try:
			file = open(filename, "r")
			size = os.stat(filename)[ST_SIZE]
		except IOError, e:
			raise ParameterError("%s: %s" % (filename, e.strerror))
		headers = SortedDict()
		headers["content-length"] = size
		request = self.create_request("OBJECT_PUT", bucket = bucket, object = object, headers = headers)
		response = self.send_file(request, file)
		response["size"] = size
		return response

	def object_get(self, filename, bucket, object):
		try:
			file = open(filename, "w")
		except IOError, e:
			raise ParameterError("%s: %s" % (filename, e.strerror))
		request = self.create_request("OBJECT_GET", bucket = bucket, object = object)
		response = self.recv_file(request, file)
		response["size"] = int(response["headers"]["content-length"])
		return response

	def object_delete(self, bucket, object):
		request = self.create_request("OBJECT_DELETE", bucket = bucket, object = object)
		response = self.send_request(request)
		return response

	def create_request(self, operation, bucket = None, object = None, headers = None):
		resource = "/"
		if bucket:
			resource += str(bucket)
			if object:
				resource += "/"+str(object)

		if not headers:
			headers = SortedDict()

		if headers.has_key("date"):
			if not headers.has_key("x-amz-date"):
				headers["x-amz-date"] = headers["date"]
			del(headers["date"])
		
		if not headers.has_key("x-amz-date"):
			headers["x-amz-date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z", time.gmtime(time.time()))

		method_string = S3.http_methods.getkey(S3.operations[operation] & S3.http_methods["MASK"])
		signature = self.sign_headers(method_string, resource, headers)
		headers["Authorization"] = "AWS "+self.config.access_key+":"+signature
		return (method_string, resource, headers)
	
	def send_request(self, request):
		method_string, resource, headers = request
		info("Processing request, please wait...")
		conn = httplib.HTTPConnection(self.config.host)
		conn.request(method_string, resource, {}, headers)
		response = {}
		http_response = conn.getresponse()
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = convertTupleListToDict(http_response.getheaders())
		response["data"] =  http_response.read()
		conn.close()
		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)
		return response

	def send_file(self, request, file):
		method_string, resource, headers = request
		info("Sending file '%s', please wait..." % file.name)
		conn = httplib.HTTPConnection(self.config.host)
		conn.connect()
		conn.putrequest(method_string, resource)
		for header in headers.keys():
			conn.putheader(header, str(headers[header]))
		conn.endheaders()
		size_left = size_total = headers.get("content-length")
		while (size_left > 0):
			debug("SendFile: Reading up to %d bytes from '%s'" % (AwsConfig.send_chunk, file.name))
			data = file.read(AwsConfig.send_chunk)
			debug("SendFile: Sending %d bytes to the server" % len(data))
			conn.send(data)
			size_left -= len(data)
			info("Sent %d bytes (%d %% of %d)" % (
				(size_total - size_left),
				(size_total - size_left) * 100 / size_total,
				size_total))
		response = {}
		http_response = conn.getresponse()
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = convertTupleListToDict(http_response.getheaders())
		response["data"] =  http_response.read()
		conn.close()
		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)
		return response

	def recv_file(self, request, file):
		method_string, resource, headers = request
		info("Receiving file '%s', please wait..." % file.name)
		conn = httplib.HTTPConnection(self.config.host)
		conn.connect()
		conn.putrequest(method_string, resource)
		for header in headers.keys():
			conn.putheader(header, str(headers[header]))
		conn.endheaders()
		response = {}
		http_response = conn.getresponse()
		response["status"] = http_response.status
		response["reason"] = http_response.reason
		response["headers"] = convertTupleListToDict(http_response.getheaders())
		if response["status"] < 200 or response["status"] > 299:
			raise S3Error(response)

		md5=hashlib.new("md5")
		size_left = size_total = int(response["headers"]["content-length"])
		while (size_left > 0):
			this_chunk = size_left > AwsConfig.recv_chunk and AwsConfig.recv_chunk or size_left
			debug("ReceiveFile: Receiving up to %d bytes from the server" % this_chunk)
			data = http_response.read(this_chunk)
			debug("ReceiveFile: Writing %d bytes to file '%s'" % (len(data), file.name))
			file.write(data)
			md5.update(data)
			size_left -= len(data)
			info("Received %d bytes (%d %% of %d)" % (
				(size_total - size_left),
				(size_total - size_left) * 100 / size_total,
				size_total))
		conn.close()
		response["md5"] = md5.hexdigest()
		response["md5match"] = response["headers"]["etag"].find(response["md5"]) >= 0
		debug("ReceiveFile: Computed MD5 = %s" % response["md5"])
		if not response["md5match"]:
			warning("MD5 signatures do not match: computed=%s, received=%s" % (
				response["md5"], response["headers"]["etag"]))

		return response

	def sign_headers(self, method, resource, headers):
		h  = method+"\n"
		h += headers.get("content-md5", "")+"\n"
		h += headers.get("content-type", "")+"\n"
		h += headers.get("date", "")+"\n"
		for header in headers.keys():
			if header.startswith("x-amz-"):
				h += header+":"+str(headers[header])+"\n"
		h += resource
		return base64.encodestring(hmac.new(self.config.secret_key, h, hashlib.sha1).digest()).strip()

	def check_bucket_name(self, bucket):
		if re.compile("[^A-Za-z0-9\._-]").search(bucket):
			raise ParameterError("Bucket name '%s' contains unallowed characters" % bucket)
		if len(bucket) < 3:
			raise ParameterError("Bucket name '%s' is too short (min 3 characters)" % bucket)
		if len(bucket) > 255:
			raise ParameterError("Bucket name '%s' is too long (max 255 characters)" % bucket)
		return True

	def compose_uri(self, bucket, object = None):
		if AwsConfig.show_uri:
			uri = "s3://" + bucket
			if object:
				uri += "/"+object
			return uri
		else:
			return object and object or bucket

	def parse_s3_uri(self, uri):
		match = re.compile("^s3://([^/]*)/?(.*)").match(uri)
		if match:
			return (True,) + match.groups()
		else:
			return (False, "", "")

def output(message):
	print message

def cmd_buckets_list_all(args):
	s3 = S3(AwsConfig())
	response = s3.list_all_buckets()

	for bucket in response["list"]:
		output("%s  %s" % (
			formatDateTime(bucket["CreationDate"]),
			s3.compose_uri(bucket["Name"]),
			))

def cmd_buckets_list_all_all(args):
	s3 = S3(AwsConfig())
	response = s3.list_all_buckets()

	for bucket in response["list"]:
		cmd_bucket_list([bucket["Name"]])
		output("")


def cmd_bucket_list(args):
	s3 = S3(AwsConfig())
	isuri, bucket, object = s3.parse_s3_uri(args[0])
	if not isuri:
		bucket = args[0]
	output("Bucket '%s':" % bucket)
	try:
		response = s3.bucket_list(bucket)
	except S3Error, e:
		if S3.codes.has_key(e.Code):
			error(S3.codes[e.Code] % bucket)
			return
		else:
			raise
	for object in response["list"]:
		size, size_coeff = formatSize(object["Size"], AwsConfig.human_readable_sizes)
		output("%s  %s%s  %s" % (
			formatDateTime(object["LastModified"]),
			str(size).rjust(8), size_coeff.ljust(1),
			s3.compose_uri(bucket, object["Key"]),
			))

def cmd_bucket_create(args):
	s3 = S3(AwsConfig())
	isuri, bucket, object = s3.parse_s3_uri(args[0])
	if not isuri:
		bucket = args[0]
	try:
		response = s3.bucket_create(bucket)
	except S3Error, e:
		if S3.codes.has_key(e.Code):
			error(S3.codes[e.Code] % bucket)
			return
		else:
			raise
	output("Bucket '%s' created" % bucket)

def cmd_bucket_delete(args):
	s3 = S3(AwsConfig())
	isuri, bucket, object = s3.parse_s3_uri(args[0])
	if not isuri:
		bucket = args[0]
	try:
		response = s3.bucket_delete(bucket)
	except S3Error, e:
		if S3.codes.has_key(e.Code):
			error(S3.codes[e.Code] % bucket)
			return
		else:
			raise
	output("Bucket '%s' removed" % bucket)

def cmd_object_put(args):
	s3 = S3(AwsConfig())

	s3uri = args.pop()
	files = args[:]

	isuri, bucket, object = s3.parse_s3_uri(s3uri)
	if not isuri:
		raise ParameterError("Expecting S3 URI instead of '%s'" % s3uri)

	if len(files) > 1 and object != "" and not AwsConfig.force:
		error("When uploading multiple files the last argument must")
		error("be a S3 URI specifying just the bucket name")
		error("WITHOUT object name!")
		error("Alternatively use --force argument and the specified")
		error("object name will be prefixed to all stored filanames.")
		exit(1)

	for file in files:
		if len(files) > 1:
			object_final = object + os.path.basename(file)
		elif object == "":
			object_final = os.path.basename(file)
		else:
			object_final = object
		response = s3.object_put(file, bucket, object_final)
		output("File '%s' stored as %s (%d bytes)" %
			(file, s3.compose_uri(bucket, object_final), response["size"]))

def cmd_object_get(args):
	s3 = S3(AwsConfig())
	s3uri = args.pop(0)
	isuri, bucket, object = s3.parse_s3_uri(s3uri)
	if not isuri or not bucket or not object:
		raise ParameterError("Expecting S3 object URI instead of '%s'" % s3uri)
	destination = len(args) > 0 and args.pop(0) or object
	if os.path.isdir(destination):
		destination += ("/" + object)
	if not AwsConfig.force and os.path.exists(destination):
		raise ParameterError("File %s already exists. Use --force to overwrite it" % destination)
	response = s3.object_get(destination, bucket, object)
	output("Object %s saved as '%s' (%d bytes)" %
		(s3uri, destination, response["size"]))

def cmd_object_del(args):
	s3 = S3(AwsConfig())
	s3uri = args.pop(0)
	isuri, bucket, object = s3.parse_s3_uri(s3uri)
	if not isuri or not bucket or not object:
		raise ParameterError("Expecting S3 object URI instead of '%s'" % s3uri)
	response = s3.object_delete(bucket, object)
	output("Object %s deleted" % s3uri)

commands = {
	"lb" : ("List all buckets", cmd_buckets_list_all, 0),
	"cb" : ("Create bucket", cmd_bucket_create, 1),
	"mb" : ("Create bucket", cmd_bucket_create, 1),
	"rb" : ("Remove bucket", cmd_bucket_delete, 1),
	"db" : ("Remove bucket", cmd_bucket_delete, 1),
	"ls" : ("List objects in bucket", cmd_bucket_list, 1),
	"la" : ("List all object in all buckets", cmd_buckets_list_all_all, 0),
	"put": ("Put file into bucket", cmd_object_put, 2),
	"get": ("Get file from bucket", cmd_object_get, 1),
	"del": ("Delete file from bucket", cmd_object_del, 1),
	}

if __name__ == '__main__':
	if float("%d.%d" %(sys.version_info[0], sys.version_info[1])) < 2.5:
		sys.stderr.write("ERROR: Python 2.5 or higher required, sorry.\n")
		exit(1)

	default_verbosity = AwsConfig.verbosity
	optparser = OptionParser()
	optparser.set_defaults(config=os.getenv("HOME")+"/.s3cfg")
	optparser.add_option("-c", "--config", dest="config", metavar="FILE", help="Config file name")
	optparser.set_defaults(verbosity = default_verbosity)
	optparser.add_option("-d", "--debug", dest="verbosity", action="store_const", const=logging.DEBUG, help="Enable debug output")
	optparser.add_option("-v", "--verbose", dest="verbosity", action="store_const", const=logging.INFO, help="Enable verbose output")
	optparser.set_defaults(human_readable = False)
	optparser.add_option("-H", "--human-readable", dest="human_readable", action="store_true", help="Print sizes in human readable form")
	optparser.set_defaults(force = False)
	optparser.add_option("-f", "--force", dest="force", action="store_true", help="Force overwrite and other dangerous operations")
	optparser.set_defaults(show_uri = False)
	optparser.add_option("-u", "--show-uri", dest="show_uri", action="store_true", help="Show complete S3 URI in listings")

	(options, args) = optparser.parse_args()

	## Some mucking with logging levels to enable 
	## debugging/verbose output for config file parser on request
	logging.basicConfig(level=options.verbosity, format='%(levelname)s: %(message)s')
	
	## Now finally parse the config file
	AwsConfig(options.config)

	## And again some logging level adjustments
	## according to configfile and command line parameters
	if options.verbosity != default_verbosity:
		AwsConfig.verbosity = options.verbosity
	logging.root.setLevel(AwsConfig.verbosity)

	## Update AwsConfig with other parameters
	AwsConfig.human_readable_sizes = options.human_readable
	AwsConfig.force = options.force
	AwsConfig.show_uri = options.show_uri

	if len(args) < 1:
		error("Missing command. Please run with --help for more information.")
		exit(1)

	command = args.pop(0)
	try:
		debug("Command: " + commands[command][0])
		## We must do this lookup in extra step to 
		## avoid catching all KeyError exceptions
		## from inner functions.
		cmd_func = commands[command][1]
	except KeyError, e:
		error("Invalid command: %s" % e)
		exit(1)

	if len(args) < commands[command][2]:
		error("Not enough paramters for command '%s'" % command)
		exit(1)

	try:
		cmd_func(args)
	except S3Error, e:
		error("S3 error: " + str(e))
	except ParameterError, e:
		error("Parameter problem: " + str(e))


