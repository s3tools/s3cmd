#!/usr/bin/env python

import httplib2
import sys
import os
import logging
import time
import base64
import hmac
import hashlib
import httplib

from optparse import OptionParser
from logging import debug, info, warn, error
import elementtree.ElementTree as ET

## Our modules
from utils import *
from SortedDict import SortedDict
from BidirMap import BidirMap
from ConfigParser import ConfigParser

class AwsConfig:
	access_key = ""
	secret_key = ""
	host = "s3.amazonaws.com"
	verbosity = logging.WARNING

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

class S3Error (Exception):
	def __init__(self, response):
		#Exception.__init__(self)
		self.status = response["status"]
		self.reason = response["reason"]
		tree = ET.fromstring(response["data"])
		for child in tree.getchildren():
			if child.text != "":
				debug(child.tag + ": " + repr(child.text))
				self.__setattr__(child.tag, child.text)

	def __str__(self):
		return "%d (%s): %s" % (self.status, self.reason, self.Code)

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
		response["data"] =  http_response.read()
		conn.close()
		if response["status"] != 200:
			raise S3Error(response)
		return response

	def sign_headers(self, method, resource, headers):
		h  = method+"\n"
		h += headers.pop("content-md5", "")+"\n"
		h += headers.pop("content-type", "")+"\n"
		h += headers.pop("date", "")+"\n"
		for header in headers.keys():
			if header.startswith("x-amz-"):
				h += header+":"+str(headers[header])+"\n"
		h += resource
		return base64.encodestring(hmac.new(self.config.secret_key, h, hashlib.sha1).digest()).strip()

def cmd_buckets_list_all(args):
	s3 = S3(AwsConfig())
	response = s3.list_all_buckets()

	maxlen = 0
	for bucket in response["list"]:
		if len(bucket["Name"]) > maxlen:
			maxlen = len(bucket["Name"])
	for bucket in response["list"]:
		print "%s  %s" % (
			formatDateTime(bucket["CreationDate"]),
			bucket["Name"].ljust(maxlen),
			)

def cmd_bucket_list(args):
	bucket = args[0]
	s3 = S3(AwsConfig())
	try:
		response = s3.bucket_list(bucket)
	except S3Error, e:
		codes = {
			"NoSuchBucket" : "Bucket '%s' does not exist",
			"AccessDenied" : "Access to bucket '%s' was denied",
			}
		if codes.has_key(e.Code):
			error(codes[e.Code] % bucket)
			return
		else:
			raise
	maxlen = 0
	for object in response["list"]:
		if len(object["Key"]) > maxlen:
			maxlen = len(object["Key"])
	for object in response["list"]:
		size, size_coeff = formatSize(object["Size"], True)
		print "%s  %s%s  %s" % (
			formatDateTime(object["LastModified"]),
			str(size).rjust(4), size_coeff.ljust(1),
			object["Key"].ljust(maxlen),
			)


commands = {
	"la" : ("List all buckets", cmd_buckets_list_all, 0),
	"lb" : ("List objects in bucket", cmd_bucket_list, 1),
#	"cb" : ("Create bucket", cmd_bucket_create, 1),
#	"rb" : ("Remove bucket", cmd_bucket_remove, 1)
	}

if __name__ == '__main__':
	optparser = OptionParser()
	optparser.set_defaults(config=os.getenv("HOME")+"/.s3cfg")
	optparser.add_option("-c", "--config", dest="config", metavar="FILE", help="Config file name")
	optparser.add_option("-d", "--debug", action="store_true", help="Enable debug output")
	(options, args) = optparser.parse_args()

	## Some mucking with logging levels to enable 
	## debugging output for config file parser on request
	init_logging_level = logging.INFO
	if options.debug: init_logging_level = logging.DEBUG
	logging.basicConfig(level=init_logging_level, format='%(levelname)s: %(message)s')
	
	## Now finally parse the config file
	AwsConfig(options.config)

	## And again some logging level adjustments, argh.
	if options.debug:
		AwsConfig.verbosity = logging.DEBUG
	logging.root.setLevel(AwsConfig.verbosity)

	if len(args) < 1:
		error("Missing command. Please run with --help for more information.")
		exit(1)

	command = args.pop(0)
	try:
		debug("Command: " + commands[command][0])
		## We must do this lookup in extra step to 
		## avoid catching all KeyError exceptions
		## from inner functions here. 
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

