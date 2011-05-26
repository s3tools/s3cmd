## Amazon S3 Multipart upload support
## Author: Jerome Leclanche <jerome.leclanche@gmail.com>
## License: GPL Version 2

import os
from stat import ST_SIZE
from logging import debug, info, warning, error
from Utils import getTextFromXml

class MultiPartUpload(object):
	
	MIN_CHUNK_SIZE = 5242880 # 5MB
	MAX_CHUNK_SIZE = 5368709120 # 5GB
	MAX_CHUNKS = 100
	MAX_FILE_SIZE = 42949672960 # 5TB
	
	def __init__(self, bucket, file, uri):
		self.bucket = bucket
		self.file = file
		self.uri = uri
		self.upload_id = None
	
	def initiate_multipart_upload(self):
		"""
		Begin a multipart upload
		http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadInitiate.html
		"""
		request = self.bucket.create_request("OBJECT_POST", uri = self.uri, extra = "?uploads")
		response = self.bucket.send_request(request)
		data = response["data"]
		bucket, key, upload_id = getTextFromXml(data, "Bucket"), getTextFromXml(data, "Key"), getTextFromXml(data, "UploadId")
		self.upload_id = upload_id
		return bucket, key, upload_id
	
	def upload_all_parts(self, num_processes = 1, chunk_size = MIN_CHUNK_SIZE):
		"""
		Execute a full multipart upload on a file
		Returns the id/etag dict
		TODO use num_processes to thread it
		"""
		if not self.upload_id:
			raise RuntimeError("Attempting to use a multipart upload that has not been initiated.")
		
		chunk_size = max(self.MIN_CHUNK_SIZE, chunk_size)
		id = 1
		parts = {}
		
		while True:
			if id == self.MAX_CHUNKS:
				data = self.file.read(-1)
			else:
				data = self.file.read(chunk_size)
			if not data:
				break
			parts[id] = self.upload_part(data, id)
			id += 1
		
		return parts
	
	def upload_part(self, data, id):
		"""
		Upload a file chunk
		http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadUploadPart.html
		"""
		# TODO implement Content-MD5
		content_length = str(len(data))
		debug("Uploading part %i of %r (%s bytes)" % (id, self.upload_id, content_length))
		headers = { "Content-Length": content_length }
		query_string = "?partNumber=%i&uploadId=%s" % (id, self.upload_id)
		request = self.bucket.create_request("OBJECT_PUT", uri = self.uri, headers = headers, extra = query_string)
		response = self.bucket.send_request(request, body = data)
		
		return response["headers"]["etag"]
	
	def complete_multipart_upload(self, parts):
		"""
		Finish a multipart upload
		http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadComplete.html
		"""
		parts_xml = []
		part_xml = "<Part><PartNumber>%i</PartNumber><ETag>%s</ETag></Part>"
		for id, etag in parts.items():
			parts_xml.append(part_xml % (id, etag))
		body = "<CompleteMultipartUpload>%s</CompleteMultipartUpload>" % ("".join(parts_xml))
		
		headers = { "Content-Length": len(body) }
		request = self.bucket.create_request("OBJECT_POST", uri = self.uri, headers = headers, extra = "?uploadId=%s" % (self.upload_id))
		response = self.bucket.send_request(request, body = body)
