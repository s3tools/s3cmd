# -*- coding: utf-8 -*-

## Amazon S3 Multipart upload support
## Author: Jerome Leclanche <jerome.leclanche@gmail.com>
## License: GPL Version 2

from __future__ import absolute_import

import os
import sys
from stat import ST_SIZE
from logging import debug, info, warning, error
from .Utils import getTextFromXml, getTreeFromXml, formatSize, unicodise, deunicodise, calculateChecksum, parseNodes, encode_to_s3

class MultiPartUpload(object):

    MIN_CHUNK_SIZE_MB = 5       # 5MB
    MAX_CHUNK_SIZE_MB = 5120    # 5GB
    MAX_FILE_SIZE = 42949672960 # 5TB

    def __init__(self, s3, file, uri, headers_baseline = {}):
        self.s3 = s3
        self.file = file
        self.uri = uri
        self.parts = {}
        self.headers_baseline = headers_baseline
        self.upload_id = self.initiate_multipart_upload()

    def get_parts_information(self, uri, upload_id):
        multipart_response = self.s3.list_multipart(uri, upload_id)
        tree = getTreeFromXml(multipart_response['data'])

        parts = dict()
        for elem in parseNodes(tree):
            try:
                parts[int(elem['PartNumber'])] = {'checksum': elem['ETag'], 'size': elem['Size']}
            except KeyError:
                pass

        return parts

    def get_unique_upload_id(self, uri):
        upload_id = None
        multipart_response = self.s3.get_multipart(uri)
        tree = getTreeFromXml(multipart_response['data'])
        for mpupload in parseNodes(tree):
            try:
                mp_upload_id = mpupload['UploadId']
                mp_path = mpupload['Key']
                info("mp_path: %s, object: %s" % (mp_path, uri.object()))
                if mp_path == uri.object():
                    if upload_id is not None:
                        raise ValueError("More than one UploadId for URI %s.  Disable multipart upload, or use\n %s multipart %s\nto list the Ids, then pass a unique --upload-id into the put command." % (uri, sys.argv[0], uri))
                    upload_id = mp_upload_id
            except KeyError:
                pass

        return upload_id

    def initiate_multipart_upload(self):
        """
        Begin a multipart upload
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadInitiate.html
        """
        if self.s3.config.upload_id is not None:
            self.upload_id = self.s3.config.upload_id
        elif self.s3.config.put_continue:
            self.upload_id = self.get_unique_upload_id(self.uri)
        else:
            self.upload_id = None

        if self.upload_id is None:
            request = self.s3.create_request("OBJECT_POST", uri = self.uri, headers = self.headers_baseline, extra = "?uploads")
            response = self.s3.send_request(request)
            data = response["data"]
            self.upload_id = getTextFromXml(data, "UploadId")

        return self.upload_id

    def upload_all_parts(self, extra_label=''):
        """
        Execute a full multipart upload on a file
        Returns the seq/etag dict
        TODO use num_processes to thread it
        """
        if not self.upload_id:
            raise RuntimeError("Attempting to use a multipart upload that has not been initiated.")

        self.chunk_size = self.s3.config.multipart_chunk_size_mb * 1024 * 1024
        filename = unicodise(self.file.name)

        if filename != "<stdin>":
                size_left = file_size = os.stat(deunicodise(filename))[ST_SIZE]
                nr_parts = file_size // self.chunk_size + (file_size % self.chunk_size and 1)
                debug("MultiPart: Uploading %s in %d parts" % (filename, nr_parts))
        else:
            debug("MultiPart: Uploading from %s" % filename)

        remote_statuses = dict()
        if self.s3.config.put_continue:
            remote_statuses = self.get_parts_information(self.uri, self.upload_id)

        if extra_label:
            extra_label = u' ' + extra_label
        seq = 1
        if filename != "<stdin>":
            while size_left > 0:
                offset = self.chunk_size * (seq - 1)
                current_chunk_size = min(file_size - offset, self.chunk_size)
                size_left -= current_chunk_size
                labels = {
                    'source' : filename,
                    'destination' : self.uri.uri(),
                    'extra' : "[part %d of %d, %s]%s" % (seq, nr_parts, "%d%sB" % formatSize(current_chunk_size, human_readable = True), extra_label)
                }
                try:
                    self.upload_part(seq, offset, current_chunk_size, labels, remote_status = remote_statuses.get(seq))
                except:
                    error(u"\nUpload of '%s' part %d failed. Use\n  %s abortmp %s %s\nto abort the upload, or\n  %s --upload-id %s put ...\nto continue the upload."
                          % (filename, seq, sys.argv[0], self.uri, self.upload_id, sys.argv[0], self.upload_id))
                    raise
                seq += 1
        else:
            while True:
                buffer = self.file.read(self.chunk_size)
                offset = 0 # send from start of the buffer
                current_chunk_size = len(buffer)
                labels = {
                    'source' : filename,
                    'destination' : self.uri.uri(),
                    'extra' : "[part %d, %s]" % (seq, "%d%sB" % formatSize(current_chunk_size, human_readable = True))
                }
                if len(buffer) == 0: # EOF
                    break
                try:
                    self.upload_part(seq, offset, current_chunk_size, labels, buffer, remote_status = remote_statuses.get(seq))
                except:
                    error(u"\nUpload of '%s' part %d failed. Use\n  %s abortmp %s %s\nto abort, or\n  %s --upload-id %s put ...\nto continue the upload."
                          % (filename, seq, sys.argv[0], self.uri, self.upload_id, sys.argv[0], self.upload_id))
                    raise
                seq += 1

        debug("MultiPart: Upload finished: %d parts", seq - 1)

    def upload_part(self, seq, offset, chunk_size, labels, buffer = '', remote_status = None):
        """
        Upload a file chunk
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadUploadPart.html
        """
        # TODO implement Content-MD5
        debug("Uploading part %i of %r (%s bytes)" % (seq, self.upload_id, chunk_size))

        if remote_status is not None:
            if int(remote_status['size']) == chunk_size:
                checksum = calculateChecksum(buffer, self.file, offset, chunk_size, self.s3.config.send_chunk)
                remote_checksum = remote_status['checksum'].strip('"\'')
                if remote_checksum == checksum:
                    warning("MultiPart: size and md5sum match for %s part %d, skipping." % (self.uri, seq))
                    self.parts[seq] = remote_status['checksum']
                    return
                else:
                    warning("MultiPart: checksum (%s vs %s) does not match for %s part %d, reuploading."
                            % (remote_checksum, checksum, self.uri, seq))
            else:
                warning("MultiPart: size (%d vs %d) does not match for %s part %d, reuploading."
                        % (int(remote_status['size']), chunk_size, self.uri, seq))

        headers = { "content-length": str(chunk_size) }
        query_string = "?partNumber=%i&uploadId=%s" % (seq, self.upload_id)
        request = self.s3.create_request("OBJECT_PUT", uri = self.uri, headers = headers, extra = query_string)
        response = self.s3.send_file(request, self.file, labels, buffer, offset = offset, chunk_size = chunk_size)
        self.parts[seq] = response["headers"].get('etag', '').strip('"\'')
        return response

    def complete_multipart_upload(self):
        """
        Finish a multipart upload
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadComplete.html
        """
        debug("MultiPart: Completing upload: %s" % self.upload_id)

        parts_xml = []
        part_xml = "<Part><PartNumber>%i</PartNumber><ETag>%s</ETag></Part>"
        for seq, etag in self.parts.items():
            parts_xml.append(part_xml % (seq, etag))
        body = "<CompleteMultipartUpload>%s</CompleteMultipartUpload>" % ("".join(parts_xml))

        headers = { "content-length": str(len(body)) }
        request = self.s3.create_request("OBJECT_POST", uri = self.uri, headers = headers, extra = "?uploadId=%s" % self.upload_id, body = body)
        response = self.s3.send_request(request)

        return response

    def abort_upload(self):
        """
        Abort multipart upload
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadAbort.html
        """
        debug("MultiPart: Aborting upload: %s" % self.upload_id)
        #request = self.s3.create_request("OBJECT_DELETE", uri = self.uri, extra = "?uploadId=%s" % (self.upload_id))
        #response = self.s3.send_request(request)
        response = None
        return response

# vim:et:ts=4:sts=4:ai
