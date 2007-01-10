#!/usr/bin/env python

import httplib2
import sys
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

class AwsConfig:
	access_key = "<Put Your Access Key Here>"
	secret_key = "<Put Your Secret Key Here>"
	host = "s3.amazonaws.com"
	verbose = False

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
		return response
	
	def bucket_list(self, bucket):
		request = self.create_request("BUCKET_LIST", bucket = bucket)
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
	tree = ET.fromstring(response["data"])
	xmlns = getNameSpace(tree)
	nodes = tree.findall('.//%sBucket' % xmlns)
	buckets = parseNodes(nodes, xmlns)
	maxlen = 0
	for bucket in buckets:
		if len(bucket["Name"]) > maxlen:
			maxlen = len(bucket["Name"])
	for bucket in buckets:
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
		if e.Code == "NoSuchBucket":
			error("Bucket '%s' does not exist" % bucket)
			return
		else:
			raise
	tree = ET.fromstring(response["data"])
	xmlns = getNameSpace(tree)
	nodes = tree.findall('.//%sContents' % xmlns)
	objects = parseNodes(nodes, xmlns)
	maxlen = 0
	for object in objects:
		if len(object["Key"]) > maxlen:
			maxlen = len(object["Key"])
	for object in objects:
		size, size_coeff = formatSize(object["Size"], True)
		print "%s  %s%s  %s" % (
			formatDateTime(object["LastModified"]),
			str(size).rjust(4), size_coeff.ljust(1),
			object["Key"].ljust(maxlen),
			)


commands = {
	"la" : ("List all buckets", cmd_buckets_list_all),
	"lb" : ("List objects in bucket", cmd_bucket_list),
#	"cb" : ("Create bucket", cmd_bucket_create),
#	"rb" : ("Remove bucket", cmd_bucket_remove)
	}

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

	optparser = OptionParser()
	optparser.set_defaults(config="~/.s3fs.cfg")
	optparser.add_option("-c", "--config", dest="config", metavar="FILE", help="Config file name")
	optparser.add_option("-d", "--debug", action="store_false", help="Enable debug output")
	optparser.add_option("-v", "--verbose", action="store_false", help="Enable verbose output")
	(options, args) = optparser.parse_args()

	if len(args) < 1:
		error("Missing command. Please run with --help for more information.")
		exit(1)

	command = args[0]
	args.remove(command)
	try:
		print commands[command][0]
		commands[command][1](args)
	except KeyError, e:
		error("Invalid command: %s" % e)
	except S3Error, e:
		error("S3 error: " + str(e))

