# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

import sys
import os
import time
import errno
import base64
import mimetypes
from xml.sax import saxutils
from logging import debug, info, warning, error
from stat import ST_SIZE
from urllib import quote_plus

try:
    from hashlib import md5
except ImportError:
    from md5 import md5

from Utils import *
from SortedDict import SortedDict
from AccessLog import AccessLog
from ACL import ACL, GranteeLogDelivery
from BidirMap import BidirMap
from Config import Config
from Exceptions import *
from MultiPart import MultiPartUpload
from S3Uri import S3Uri
from ConnMan import ConnMan
from Crypto import sign_string_v2, sign_string_v4, checksum_sha256_file, checksum_sha256_buffer

try:
    from ctypes import ArgumentError
    import magic
    try:
        ## https://github.com/ahupp/python-magic
        ## Always expect unicode for python 2
        ## (has Magic class but no "open()" function)
        magic_ = magic.Magic(mime=True)
        def mime_magic_file(file):
            return magic_.from_file(file)
    except TypeError:
        try:
            ## file-5.11 built-in python bindings
            ## Sources: http://www.darwinsys.com/file/
            ## Expects unicode since version 5.19, encoded strings before
            ## we can't tell if a given copy of the magic library will take a
            ## filesystem-encoded string or a unicode value, so try first
            ## with the unicode, then with the encoded string.
            ## (has Magic class and "open()" function)
            magic_ = magic.open(magic.MAGIC_MIME)
            magic_.load()
            def mime_magic_file(file):
                try:
                    return magic_.file(file)
                except (UnicodeDecodeError, UnicodeEncodeError, ArgumentError):
                    return magic_.file(deunicodise(file))
        except AttributeError:
            ## http://pypi.python.org/pypi/filemagic
            ## Accept gracefully both unicode and encoded
            ## (has Magic class but not "mime" argument and no "open()" function )
            magic_ = magic.Magic(flags=magic.MAGIC_MIME)
            def mime_magic_file(file):
                return magic_.id_filename(file)

    except AttributeError:
        ## Older python-magic versions doesn't have a "Magic" method
        ## Only except encoded strings
        ## (has no Magic class but "open()" function)
        magic_ = magic.open(magic.MAGIC_MIME)
        magic_.load()
        def mime_magic_file(file):
            return magic_.file(deunicodise(file))

except ImportError, e:
    if 'magic' in str(e):
        magic_message = "Module python-magic is not available."
    else:
        magic_message = "Module python-magic can't be used (%s)." % e.message
    magic_message += " Guessing MIME types based on file extensions."
    magic_warned = False
    def mime_magic_file(file):
        global magic_warned
        if (not magic_warned):
            warning(magic_message)
            magic_warned = True
        return mimetypes.guess_type(file)[0]

def mime_magic(file):
    ## NOTE: So far in the code, "file" var is already unicode
    def _mime_magic(file):
        magictype = mime_magic_file(file)
        return magictype

    result = _mime_magic(file)
    if result is not None:
        if isinstance(result, str):
            if ';' in result:
                mimetype, charset = result.split(';')
                charset = charset[len('charset'):]
                result = (mimetype, charset)
            else:
                result = (result, None)
    if result is None:
        result = (None, None)
    return result

__all__ = []
class S3Request(object):
    region_map = {}

    def __init__(self, s3, method_string, resource, headers, body, params = {}):
        self.s3 = s3
        self.headers = SortedDict(headers or {}, ignore_case = True)
        if len(self.s3.config.access_token)>0:
            self.s3.config.role_refresh()
            self.headers['x-amz-security-token']=self.s3.config.access_token
        self.resource = resource
        self.method_string = method_string
        self.params = params
        self.body = body
        self.requester_pays()

    def requester_pays(self):
        if self.method_string == "GET" or self.method_string == "POST":
            if self.s3.config.requester_pays:
                self.headers['x-amz-request-payer'] = 'requester'

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

    def use_signature_v2(self):
        if self.s3.endpoint_requires_signature_v4:
            return False
        # in case of bad DNS name due to bucket name v2 will be used
        # this way we can still use capital letters in bucket names for the older regions

        if self.resource['bucket'] is None or not check_bucket_name_dns_conformity(self.resource['bucket']) or self.s3.config.signature_v2 or self.s3.fallback_to_signature_v2:
            return True
        return False

    def sign(self):
        h  = self.method_string + "\n"
        h += self.headers.get("content-md5", "")+"\n"
        h += self.headers.get("content-type", "")+"\n"
        h += self.headers.get("date", "")+"\n"
        for header in sorted(self.headers.keys()):
            if header.startswith("x-amz-"):
                h += header+":"+str(self.headers[header])+"\n"
            if header.startswith("x-emc-"):
                h += header+":"+str(self.headers[header])+"\n"
        if self.resource['bucket']:
            h += "/" + self.resource['bucket']
        h += self.resource['uri']

        if self.use_signature_v2():
            debug("Using signature v2")
            debug("SignHeaders: " + repr(h))
            signature = sign_string_v2(h)
            self.headers["Authorization"] = "AWS "+self.s3.config.access_key+":"+signature
        else:
            debug("Using signature v4")
            self.headers = sign_string_v4(self.method_string,
                                          self.s3.get_hostname(self.resource['bucket']),
                                          self.resource['uri'],
                                          self.params,
                                          S3Request.region_map.get(self.resource['bucket'], Config().bucket_location),
                                          self.headers,
                                          self.body)

    def get_triplet(self):
        self.update_timestamp()
        self.sign()
        resource = dict(self.resource)  ## take a copy
        resource['uri'] += self.format_param_str()
        return (self.method_string, resource, self.headers)

class S3(object):
    http_methods = BidirMap(
        GET = 0x01,
        PUT = 0x02,
        HEAD = 0x04,
        DELETE = 0x08,
        POST = 0x10,
        MASK = 0x1F,
    )

    targets = BidirMap(
        SERVICE = 0x0100,
        BUCKET = 0x0200,
        OBJECT = 0x0400,
        BATCH = 0x0800,
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
        OBJECT_POST = targets["OBJECT"] | http_methods["POST"],
        BATCH_DELETE = targets["BATCH"] | http_methods["POST"],
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
        self.fallback_to_signature_v2 = False
        self.endpoint_requires_signature_v4 = False

    def get_hostname(self, bucket):
        if bucket and check_bucket_name_dns_support(self.config.host_bucket, bucket):
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
        if resource['bucket'] and not check_bucket_name_dns_support(self.config.host_bucket, resource['bucket']):
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

    def bucket_list(self, bucket, prefix = None, recursive = None, uri_params = {}):
        item_list = []
        prefixes = []
        for dirs, objects in self.bucket_list_streaming(bucket, prefix, recursive, uri_params):
            item_list.extend(objects)
            prefixes.extend(dirs)

        response = {}
        response['list'] = item_list
        response['common_prefixes'] = prefixes
        return response

    def bucket_list_streaming(self, bucket, prefix = None, recursive = None, uri_params = {}):
        """ Generator that produces <dir_list>, <object_list> pairs of groups of content of a specified bucket. """
        def _list_truncated(data):
            ## <IsTruncated> can either be "true" or "false" or be missing completely
            is_truncated = getTextFromXml(data, ".//IsTruncated") or "false"
            return is_truncated.lower() != "false"

        def _get_contents(data):
            return getListFromXml(data, "Contents")

        def _get_common_prefixes(data):
            return getListFromXml(data, "CommonPrefixes")

        uri_params = uri_params.copy()
        truncated = True
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

            yield current_prefixes, current_list

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
        if bucket_location and bucket_location.strip().upper() != "US" and bucket_location.strip().lower() != "us-east-1":
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

        request = self.create_request("BUCKET_CREATE", bucket = bucket, headers = headers, body = body)
        response = self.send_request(request)
        return response

    def bucket_delete(self, bucket):
        request = self.create_request("BUCKET_DELETE", bucket = bucket)
        response = self.send_request(request)
        return response

    def get_bucket_location(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?location")
        response = self.send_request(request)
        location = getTextFromXml(response['data'], "LocationConstraint")
        if not location or location in [ "", "US" ]:
            location = "us-east-1"
        elif location == "EU":
            location = "eu-west-1"
        return location

    def get_bucket_requester_pays(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?requestPayment")
        response = self.send_request(request)
        payer = getTextFromXml(response['data'], "Payer")
        return payer

    def bucket_info(self, uri):
        response = {}
        response['bucket-location'] = self.get_bucket_location(uri)
        response['requester-pays'] = self.get_bucket_requester_pays(uri)
        return response

    def website_info(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_LIST", bucket = bucket, extra="?website")
        try:
            response = self.send_request(request)
            response['index_document'] = getTextFromXml(response['data'], ".//IndexDocument//Suffix")
            response['error_document'] = getTextFromXml(response['data'], ".//ErrorDocument//Key")
            response['website_endpoint'] = self.config.website_endpoint % {
                "bucket" : uri.bucket(),
                "location" : self.get_bucket_location(uri)}
            return response
        except S3Error, e:
            if e.status == 404:
                debug("Could not get /?website - website probably not configured for this bucket")
                return None
            raise

    def website_create(self, uri, bucket_location = None):
        bucket = uri.bucket()
        body = '<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += '  <IndexDocument>'
        body += ('    <Suffix>%s</Suffix>' % self.config.website_index)
        body += '  </IndexDocument>'
        if self.config.website_error:
            body += '  <ErrorDocument>'
            body += ('    <Key>%s</Key>' % self.config.website_error)
            body += '  </ErrorDocument>'
        body += '</WebsiteConfiguration>'

        request = self.create_request("BUCKET_CREATE", bucket = bucket, extra="?website", body = body)
        response = self.send_request(request)
        debug("Received response '%s'" % (response))

        return response

    def website_delete(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_DELETE", bucket = bucket, extra="?website")
        response = self.send_request(request)
        debug("Received response '%s'" % (response))

        if response['status'] != 204:
            raise S3ResponseError("Expected status 204: %s" % response)

        return response

    def expiration_info(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_LIST", bucket = bucket, extra="?lifecycle")
        try:
            response = self.send_request(request)
            response['prefix'] = getTextFromXml(response['data'], ".//Rule//Prefix")
            response['date'] = getTextFromXml(response['data'], ".//Rule//Expiration//Date")
            response['days'] = getTextFromXml(response['data'], ".//Rule//Expiration//Days")
            return response
        except S3Error, e:
            if e.status == 404:
                debug("Could not get /?lifecycle - lifecycle probably not configured for this bucket")
                return None
            raise

    def expiration_set(self, uri, bucket_location = None):
        if self.config.expiry_date and self.config.expiry_days:
             raise ParameterError("Expect either --expiry-day or --expiry-date")
        if not (self.config.expiry_date or self.config.expiry_days):
             if self.config.expiry_prefix:
                 raise ParameterError("Expect either --expiry-day or --expiry-date")
             debug("del bucket lifecycle")
             bucket = uri.bucket()
             request = self.create_request("BUCKET_DELETE", bucket = bucket, extra="?lifecycle")
        else:
             request = self._expiration_set(uri)
        response = self.send_request(request)
        debug("Received response '%s'" % (response))
        return response

    def _expiration_set(self, uri):
        debug("put bucket lifecycle")
        body = '<LifecycleConfiguration>'
        body += '  <Rule>'
        body += ('    <Prefix>%s</Prefix>' % self.config.expiry_prefix)
        body += ('    <Status>Enabled</Status>')
        body += ('    <Expiration>')
        if self.config.expiry_date:
            body += ('    <Date>%s</Date>' % self.config.expiry_date)
        elif self.config.expiry_days:
            body += ('    <Days>%s</Days>' % self.config.expiry_days)
        body += ('    </Expiration>')
        body += '  </Rule>'
        body += '</LifecycleConfiguration>'

        headers = SortedDict(ignore_case = True)
        headers['content-md5'] = compute_content_md5(body)
        bucket = uri.bucket()
        request =  self.create_request("BUCKET_CREATE", bucket = bucket, headers = headers, extra="?lifecycle", body = body)
        return (request)

    def _guess_content_type(self, filename):
        content_type = self.config.default_mime_type
        content_charset = None

        if filename == "-" and not self.config.default_mime_type:
            raise ParameterError("You must specify --mime-type or --default-mime-type for files uploaded from stdin.")

        if self.config.guess_mime_type:
            if self.config.use_mime_magic:
                (content_type, content_charset) = mime_magic(filename)
            else:
                (content_type, content_charset) = mimetypes.guess_type(filename)
        if not content_type:
            content_type = self.config.default_mime_type
        return (content_type, content_charset)

    def stdin_content_type(self):
        content_type = self.config.mime_type
        if content_type == '':
            content_type = self.config.default_mime_type

        content_type += "; charset=" + self.config.encoding.upper()
        return content_type

    def content_type(self, filename=None):
        # explicit command line argument always wins
        content_type = self.config.mime_type
        content_charset = None

        if filename == u'-':
            return self.stdin_content_type()
        if not content_type:
            (content_type, content_charset) = self._guess_content_type(filename)

        ## add charset to content type
        if not content_charset:
            content_charset = self.config.encoding.upper()
        if self.add_encoding(filename, content_type) and content_charset is not None:
            content_type = content_type + "; charset=" + content_charset

        return content_type

    def add_encoding(self, filename, content_type):
        if 'charset=' in content_type:
           return False
        exts = self.config.add_encoding_exts.split(',')
        if exts[0]=='':
            return False
        parts = filename.rsplit('.',2)
        if len(parts) < 2:
            return False
        ext = parts[1]
        if ext in exts:
            return True
        else:
            return False

    def object_put(self, filename, uri, extra_headers = None, extra_label = ""):
        # TODO TODO
        # Make it consistent with stream-oriented object_get()
        if uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % uri.type)

        if filename != "-" and not os.path.isfile(deunicodise(filename)):
            raise InvalidFileError(u"%s is not a regular file" % filename)
        try:
            if filename == "-":
                file = sys.stdin
                size = 0
            else:
                file = open(deunicodise(filename), "rb")
                size = os.stat(deunicodise(filename))[ST_SIZE]
        except (IOError, OSError), e:
            raise InvalidFileError(u"%s: %s" % (filename, e.strerror))

        headers = SortedDict(ignore_case = True)
        if extra_headers:
            headers.update(extra_headers)

        ## Set server side encryption
        if self.config.server_side_encryption:
            headers["x-amz-server-side-encryption"] = "AES256"

        ## MIME-type handling
        headers["content-type"] = self.content_type(filename=filename)

        ## Other Amazon S3 attributes
        if self.config.acl_public:
            headers["x-amz-acl"] = "public-read"
        if self.config.reduced_redundancy:
            headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY"

        ## Multipart decision
        multipart = False
        if not self.config.enable_multipart and filename == "-":
            raise ParameterError("Multi-part upload is required to upload from stdin")
        if self.config.enable_multipart:
            if size > self.config.multipart_chunk_size_mb * 1024 * 1024 or filename == "-":
                multipart = True
        if multipart:
            # Multipart requests are quite different... drop here
            return self.send_file_multipart(file, headers, uri, size)

        ## Not multipart...
        if self.config.put_continue:
            # Note, if input was stdin, we would be performing multipart upload.
            # So this will always work as long as the file already uploaded was
            # not uploaded via MultiUpload, in which case its ETag will not be
            # an md5.
            try:
                info = self.object_info(uri)
            except:
                info = None

            if info is not None:
                remote_size = long(info['headers']['content-length'])
                remote_checksum = info['headers']['etag'].strip('"\'')
                if size == remote_size:
                    checksum = calculateChecksum('', file, 0, size, self.config.send_chunk)
                    if remote_checksum == checksum:
                        warning("Put: size and md5sum match for %s, skipping." % uri)
                        return
                    else:
                        warning("MultiPart: checksum (%s vs %s) does not match for %s, reuploading."
                                % (remote_checksum, checksum, uri))
                else:
                    warning("MultiPart: size (%d vs %d) does not match for %s, reuploading."
                            % (remote_size, size, uri))

        headers["content-length"] = str(size)
        request = self.create_request("OBJECT_PUT", uri = uri, headers = headers)
        labels = { 'source' : filename, 'destination' : uri.uri(), 'extra' : extra_label }
        response = self.send_file(request, file, labels)
        return response

    def object_get(self, uri, stream, dest_name, start_position = 0, extra_label = ""):
        if uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
        request = self.create_request("OBJECT_GET", uri = uri)
        labels = { 'source' : uri.uri(), 'destination' : dest_name, 'extra' : extra_label }
        response = self.recv_file(request, stream, labels, start_position)
        return response

    def object_batch_delete(self, remote_list):
        """ Batch delete given a remote_list """
        uris = [remote_list[item]['object_uri_str'] for item in remote_list]
        self.object_batch_delete_uri_strs(uris)

    def object_batch_delete_uri_strs(self, uris):
        """ Batch delete given a list of object uris """
        def compose_batch_del_xml(bucket, key_list):
            body = u"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Delete>"
            for key in key_list:
                uri = S3Uri(key)
                if uri.type != "s3":
                    raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
                if not uri.has_object():
                    raise ValueError("URI '%s' has no object" % key)
                if uri.bucket() != bucket:
                    raise ValueError("The batch should contain keys from the same bucket")
                object = saxutils.escape(uri.object())
                body += u"<Object><Key>%s</Key></Object>" % object
            body += u"</Delete>"
            body = encode_to_s3(body)
            return body

        batch = uris
        if len(batch) == 0:
            raise ValueError("Key list is empty")
        bucket = S3Uri(batch[0]).bucket()
        request_body = compose_batch_del_xml(bucket, batch)
        md5_hash = md5()
        md5_hash.update(request_body)
        headers = {'content-md5': base64.b64encode(md5_hash.digest()),
                   'content-type': 'application/xml'}
        request = self.create_request("BATCH_DELETE", bucket = bucket, extra = '?delete', headers = headers, body = request_body)
        response = self.send_request(request)
        return response

    def object_delete(self, uri):
        if uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
        request = self.create_request("OBJECT_DELETE", uri = uri)
        response = self.send_request(request)
        return response

    def object_restore(self, uri):
        if uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
        body = '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-3-01">'
        body += ('  <Days>%s</Days>' % self.config.restore_days)
        body += '</RestoreRequest>'
        request = self.create_request("OBJECT_POST", uri = uri, extra = "?restore", body = body)
        response = self.send_request(request)
        debug("Received response '%s'" % (response))
        return response

    def _sanitize_headers(self, headers):
        to_remove = [
            # from http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html
            'date',
            'content-length',
            'last-modified',
            'content-md5',
            'x-amz-version-id',
            'x-amz-delete-marker',
            # other headers returned from object_info() we don't want to send
            'accept-ranges',
            'etag',
            'server',
            'x-amz-id-2',
            'x-amz-request-id',
        ]

        for h in to_remove + self.config.remove_headers:
            if h.lower() in headers:
                del headers[h.lower()]
        return headers

    def object_copy(self, src_uri, dst_uri, extra_headers = None):
        if src_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % src_uri.type)
        if dst_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % dst_uri.type)
        headers = SortedDict(ignore_case = True)
        headers['x-amz-copy-source'] = encode_to_s3("/%s/%s" % (src_uri.bucket(), self.urlencode_string(src_uri.object())))
        headers['x-amz-metadata-directive'] = "COPY"
        if self.config.acl_public:
            headers["x-amz-acl"] = "public-read"
        if self.config.reduced_redundancy:
            headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY"
        else:
            headers["x-amz-storage-class"] = "STANDARD"

        ## Set server side encryption
        if self.config.server_side_encryption:
            headers["x-amz-server-side-encryption"] = "AES256"

        if extra_headers:
            headers.update(extra_headers)

        request = self.create_request("OBJECT_PUT", uri = dst_uri, headers = headers)
        response = self.send_request(request)
        if response["data"] and getRootTagName(response["data"]) == "Error":
            #http://doc.s3.amazonaws.com/proposals/copy.html
            # Error during copy, status will be 200, so force error code 500
            response["status"] = 500
            error("Server error during the COPY operation. Overwrite response status to 500")
            raise S3Error(response)

        return response

    def object_modify(self, src_uri, dst_uri, extra_headers = None):

        if src_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % src_uri.type)
        if dst_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % dst_uri.type)

        info_response = self.object_info(src_uri)
        headers = info_response['headers']
        headers = self._sanitize_headers(headers)
        acl = self.get_acl(src_uri)

        headers['x-amz-copy-source'] = encode_to_s3("/%s/%s" % (src_uri.bucket(), self.urlencode_string(src_uri.object())))
        headers['x-amz-metadata-directive'] = "REPLACE"

        # cannot change between standard and reduced redundancy with a REPLACE.

        ## Set server side encryption
        if self.config.server_side_encryption:
            headers["x-amz-server-side-encryption"] = "AES256"

        if extra_headers:
            headers.update(extra_headers)

        if self.config.mime_type:
            headers["content-type"] = self.config.mime_type

        request = self.create_request("OBJECT_PUT", uri = src_uri, headers = headers)
        response = self.send_request(request)
        if response["data"] and getRootTagName(response["data"]) == "Error":
            #http://doc.s3.amazonaws.com/proposals/copy.html
            # Error during modify, status will be 200, so force error code 500
            response["status"] = 500
            error("Server error during the MODIFY operation. Overwrite response status to 500")
            raise S3Error(response)

        self.set_acl(src_uri, acl)

        return response

    def object_move(self, src_uri, dst_uri, extra_headers = None):
        response_copy = self.object_copy(src_uri, dst_uri, extra_headers)
        debug("Object %s copied to %s" % (src_uri, dst_uri))
        if not response_copy["data"] or getRootTagName(response_copy["data"]) == "CopyObjectResult":
            self.object_delete(src_uri)
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
        # dreamhost doesn't support set_acl properly
        if 'objects.dreamhost.com' in self.config.host_base:
            return { 'status' : 501 } # not implemented

        body = str(acl)
        debug(u"set_acl(%s): acl-xml: %s" % (uri, body))

        headers = {'content-type': 'application/xml'}
        if uri.has_object():
            request = self.create_request("OBJECT_PUT", uri = uri, extra = "?acl", headers = headers, body = body)
        else:
            request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(), extra = "?acl", headers = headers, body = body)

        response = self.send_request(request)
        return response

    def get_policy(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?policy")
        response = self.send_request(request)
        return response['data']

    def set_policy(self, uri, policy):
        headers = {}
        # TODO check policy is proper json string
        headers['content-type'] = 'application/json'
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      extra = "?policy", headers=headers, body = policy)
        response = self.send_request(request)
        return response

    def delete_policy(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri, extra = "?policy")
        debug(u"delete_policy(%s)" % uri)
        response = self.send_request(request)
        return response

    def get_cors(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?cors")
        response = self.send_request(request)
        return response['data']

    def set_cors(self, uri, cors):
        headers = {}
        # TODO check cors is proper json string
        headers['content-type'] = 'application/xml'
        headers['content-md5'] = compute_content_md5(cors)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      extra = "?cors", headers=headers, body = cors)
        response = self.send_request(request)
        return response

    def delete_cors(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri, extra = "?cors")
        debug(u"delete_cors(%s)" % uri)
        response = self.send_request(request)
        return response

    def set_lifecycle_policy(self, uri, policy):
        headers = SortedDict(ignore_case = True)
        headers['content-md5'] = compute_content_md5(policy)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      extra = "?lifecycle", headers=headers, body = policy)
        debug(u"set_lifecycle_policy(%s): policy-xml: %s" % (uri, policy))
        response = self.send_request(request)
        return response

    def set_payer(self, uri):
        headers = {}
        headers['content-type'] = 'application/xml'
        body = '<RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
        if self.config.requester_pays:
            body += '<Payer>Requester</Payer>\n'
        else:
            body += '<Payer>BucketOwner</Payer>\n'
        body += '</RequestPaymentConfiguration>\n'
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      extra = "?requestPayment", body = body)
        response = self.send_request(request)
        return response

    def delete_lifecycle_policy(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri, extra = "?lifecycle")
        debug(u"delete_lifecycle_policy(%s)" % uri)
        response = self.send_request(request)
        return response

    def get_multipart(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(), extra = "?uploads")
        response = self.send_request(request)
        return response

    def abort_multipart(self, uri, id):
        request = self.create_request("OBJECT_DELETE", uri=uri,
                                      extra = ("?uploadId=%s" % id))
        response = self.send_request(request)
        return response

    def list_multipart(self, uri, id):
        request = self.create_request("OBJECT_GET", uri=uri,
                                      extra = ("?uploadId=%s" % id))
        response = self.send_request(request)
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
        accesslog = AccessLog()
        if enable:
            accesslog.enableLogging(log_target_prefix_uri)
            accesslog.setAclPublic(acl_public)
        else:
            accesslog.disableLogging()

        body = str(accesslog)
        debug(u"set_accesslog(%s): accesslog-xml: %s" % (uri, body))

        request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(), extra = "?logging", body = body)
        try:
            response = self.send_request(request)
        except S3Error, e:
            if e.info['Code'] == "InvalidTargetBucketForLogging":
                info("Setting up log-delivery ACL for target bucket.")
                self.set_accesslog_acl(S3Uri(u"s3://%s" % log_target_prefix_uri.bucket()))
                response = self.send_request(request)
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

        encoded = quote_plus(string, safe="~/")
        debug("String '%s' encoded to '%s'" % (string, encoded))
        return encoded

    def create_request(self, operation, uri = None, bucket = None, object = None, headers = None, extra = None, body = "", **params):
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

        request = S3Request(self, method_string, resource, headers, body, params)

        debug("CreateRequest: resource[uri]=" + resource['uri'])
        return request

    def _fail_wait(self, retries):
        # Wait a few seconds. The more it fails the more we wait.
        return (self._max_retries - retries + 1) * 3

    def _http_400_handler(self, request, response, fn, *args, **kwargs):
        # AWS response AuthorizationHeaderMalformed means we sent the request to the wrong region
        # get the right region out of the response and send it there.
        message = 'Unknown error'
        if 'data' in response and len(response['data']) > 0:
            failureCode = getTextFromXml(response['data'], 'Code')
            message = getTextFromXml(response['data'], 'Message')
            if failureCode == 'AuthorizationHeaderMalformed':  # we sent the request to the wrong region
                region = getTextFromXml(response['data'], 'Region')
                if region is not None:
                    S3Request.region_map[request.resource['bucket']] = region
                    info('Forwarding request to %s' % region)
                    return fn(*args, **kwargs)
                else:
                    message = u'Could not determine bucket location. Please consider using --region parameter.'

            elif failureCode == 'InvalidRequest':
                if message == 'The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.':
                    debug(u'Endpoint requires signature v4')
                    self.endpoint_requires_signature_v4 = True
                    return fn(*args, **kwargs)

            elif failureCode == 'InvalidArgument': # returned by DreamObjects on send_request and send_file,
                                                   # which doesn't support signature v4. Retry with signature v2
                if not request.use_signature_v2() and not self.fallback_to_signature_v2: # have not tried with v2 yet
                    debug(u'Falling back to signature v2')
                    self.fallback_to_signature_v2 = True
                    return fn(*args, **kwargs)

        else: # returned by DreamObjects on recv_file, which doesn't support signature v4. Retry with signature v2
            if not request.use_signature_v2() and not self.fallback_to_signature_v2: # have not tried with v2 yet
                debug(u'Falling back to signature v2')
                self.fallback_to_signature_v2 = True
                return fn(*args, **kwargs)

        raise S3Error(response)

    def _http_403_handler(self, request, response, fn, *args, **kwargs):
        message = 'Unknown error'
        if 'data' in response and len(response['data']) > 0:
            failureCode = getTextFromXml(response['data'], 'Code')
            message = getTextFromXml(response['data'], 'Message')
            if failureCode == 'AccessDenied':  # traditional HTTP 403
                if message == 'AWS authentication requires a valid Date or x-amz-date header': # message from an Eucalyptus walrus server
                    if not request.use_signature_v2() and not self.fallback_to_signature_v2: # have not tried with v2 yet
                        debug(u'Falling back to signature v2')
                        self.fallback_to_signature_v2 = True
                        return fn(*args, **kwargs)

        raise S3Error(response)

    def send_request(self, request, retries = _max_retries):
        method_string, resource, headers = request.get_triplet()

        debug("Processing request, please wait...")
        conn = None
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            uri = self.format_uri(resource)
            debug("Sending request method_string=%r, uri=%r, headers=%r, body=(%i bytes)" % (method_string, uri, headers, len(request.body or "")))
            conn.c.request(method_string, uri, request.body, headers)
            response = {}
            http_response = conn.c.getresponse()
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertTupleListToDict(http_response.getheaders())
            response["data"] =  http_response.read()
            if response["headers"].has_key("x-amz-meta-s3cmd-attrs"):
                attrs = parse_attrs_header(response["headers"]["x-amz-meta-s3cmd-attrs"])
                response["s3cmd-attrs"] = attrs
            debug("Response: " + str(response))
            ConnMan.put(conn)
        except ParameterError, e:
            raise
        except OSError:
            raise
        except (IOError, Exception), e:
            if hasattr(e, 'errno') and e.errno != errno.EPIPE:
                raise
            # close the connection and re-establish
            if conn:
                conn.counter = ConnMan.conn_max_counter
                ConnMan.put(conn)
            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                return self.send_request(request, retries - 1)
            else:
                raise S3RequestError("Request failed for: %s" % resource['uri'])

        if response["status"] == 400:
            return self._http_400_handler(request, response, self.send_request, request)
        if response["status"] == 403:
            return self._http_403_handler(request, response, self.send_request, request)
        if response["status"] == 405: # Method Not Allowed.  Don't retry.
            raise S3Error(response)

        if response["status"] == 307:
            ## RedirectPermanent
            redir_bucket = getTextFromXml(response['data'], ".//Bucket")
            redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
            self.set_hostname(redir_bucket, redir_hostname)
            info("Redirected to: %s" % (redir_hostname))
            return self.send_request(request)

        if response["status"] >= 500:
            e = S3Error(response)

            if response["status"] == 501:
                ## NotImplemented server error - no need to retry
                retries = 0

            if retries:
                warning(u"Retrying failed request: %s" % resource['uri'])
                warning(unicode(e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                return self.send_request(request, retries - 1)
            else:
                raise e

        if response["status"] < 200 or response["status"] > 299:
            raise S3Error(response)

        return response

    def send_file(self, request, file, labels, buffer = '', throttle = 0, retries = _max_retries, offset = 0, chunk_size = -1):
        method_string, resource, headers = request.get_triplet()
        if S3Request.region_map.get(request.resource['bucket'], Config().bucket_location) is None:
            s3_uri = S3Uri(u's3://' + request.resource['bucket'])
            region = self.get_bucket_location(s3_uri)
            if region is not None:
                S3Request.region_map[request.resource['bucket']] = region

        size_left = size_total = long(headers["content-length"])
        filename = unicodise(file.name)
        if self.config.progress_meter:
            progress = self.config.progress_class(labels, size_total)
        else:
            info("Sending file '%s', please wait..." % filename)
        timestamp_start = time.time()

        if buffer:
            sha256_hash = checksum_sha256_buffer(buffer, offset, size_total)
        else:
            sha256_hash = checksum_sha256_file(filename, offset, size_total)
        request.body = sha256_hash
        method_string, resource, headers = request.get_triplet()
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            conn.c.putrequest(method_string, self.format_uri(resource))
            for header in headers.keys():
                conn.c.putheader(header, str(headers[header]))
            conn.c.endheaders()
        except ParameterError, e:
            raise
        except Exception, e:
            if self.config.progress_meter:
                progress.done("failed")
            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                # Connection error -> same throttle value
                return self.send_file(request, file, labels, buffer, throttle, retries - 1, offset, chunk_size)
            else:
                raise S3UploadError("Upload failed for: %s" % resource['uri'])
        if buffer == '':
            file.seek(offset)
        md5_hash = md5()

        try:
            while (size_left > 0):
                #debug("SendFile: Reading up to %d bytes from '%s' - remaining bytes: %s" % (self.config.send_chunk, filename, size_left))
                l = min(self.config.send_chunk, size_left)
                if buffer == '':
                    data = file.read(l)
                else:
                    data = buffer

                if self.config.limitrate > 0:
                    start_time = time.time()

                md5_hash.update(data)
                conn.c.send(data)
                if self.config.progress_meter:
                    progress.update(delta_position = len(data))
                size_left -= len(data)

                #throttle
                if self.config.limitrate > 0:
                    real_duration = time.time() - start_time
                    expected_duration = float(l)/self.config.limitrate
                    throttle = max(expected_duration - real_duration, throttle)
                if throttle:
                    time.sleep(throttle)
            md5_computed = md5_hash.hexdigest()

            response = {}
            http_response = conn.c.getresponse()
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertTupleListToDict(http_response.getheaders())
            response["data"] = http_response.read()
            response["size"] = size_total
            ConnMan.put(conn)
            debug(u"Response: %s" % response)
        except ParameterError, e:
            raise
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
                return self.send_file(request, file, labels, buffer, throttle, retries - 1, offset, chunk_size)
            else:
                debug("Giving up on '%s' %s" % (filename, e))
                raise S3UploadError("Upload failed for: %s" % resource['uri'])

        timestamp_end = time.time()
        response["elapsed"] = timestamp_end - timestamp_start
        response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)

        if self.config.progress_meter:
            ## Finalising the upload takes some time -> update() progress meter
            ## to correct the average speed. Otherwise people will complain that
            ## 'progress' and response["speed"] are inconsistent ;-)
            progress.update()
            progress.done("done")

        if response["status"] == 307:
            ## RedirectPermanent
            redir_bucket = getTextFromXml(response['data'], ".//Bucket")
            redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
            self.set_hostname(redir_bucket, redir_hostname)
            info("Redirected to: %s" % (redir_hostname))
            return self.send_file(request, file, labels, buffer, offset = offset, chunk_size = chunk_size)

        if response["status"] == 400:
            return self._http_400_handler(request, response, self.send_file, request, file, labels, buffer, offset = offset, chunk_size = chunk_size)
        if response["status"] == 403:
            return self._http_403_handler(request, response, self.send_file, request, file, labels, buffer, offset = offset, chunk_size = chunk_size)

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
                    return self.send_file(request, file, labels, buffer, throttle, retries - 1, offset, chunk_size)
                else:
                    warning("Too many failures. Giving up on '%s'" % (filename))
                    raise S3UploadError

            ## Non-recoverable error
            raise S3Error(response)

        debug("MD5 sums: computed=%s, received=%s" % (md5_computed, response["headers"]["etag"]))
        if response["headers"]["etag"].strip('"\'') != md5_hash.hexdigest():
            warning("MD5 Sums don't match!")
            if retries:
                warning("Retrying upload of %s" % (filename))
                return self.send_file(request, file, labels, buffer, throttle, retries - 1, offset, chunk_size)
            else:
                warning("Too many failures. Giving up on '%s'" % (filename))
                raise S3UploadError

        return response

    def send_file_multipart(self, file, headers, uri, size):
        timestamp_start = time.time()
        upload = MultiPartUpload(self, file, uri, headers)
        upload.upload_all_parts()
        response = upload.complete_multipart_upload()
        timestamp_end = time.time()
        response["elapsed"] = timestamp_end - timestamp_start
        response["size"] = size
        response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)
        if response["data"] and getRootTagName(response["data"]) == "Error":
            #http://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadComplete.html
            # Error Complete Multipart UPLOAD, status may be 200
            # raise S3UploadError
            raise S3UploadError(getTextFromXml(response["data"], 'Message'))
        return response

    def recv_file(self, request, stream, labels, start_position = 0, retries = _max_retries):
        method_string, resource, headers = request.get_triplet()
        filename = unicodise(stream.name)
        if self.config.progress_meter:
            progress = self.config.progress_class(labels, 0)
        else:
            info("Receiving file '%s', please wait..." % filename)
        timestamp_start = time.time()
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            conn.c.putrequest(method_string, self.format_uri(resource))
            for header in headers.keys():
                conn.c.putheader(header, str(headers[header]))
            if start_position > 0:
                debug("Requesting Range: %d .. end" % start_position)
                conn.c.putheader("Range", "bytes=%d-" % start_position)
            conn.c.endheaders()
            response = {}
            http_response = conn.c.getresponse()
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertTupleListToDict(http_response.getheaders())
            if response["headers"].has_key("x-amz-meta-s3cmd-attrs"):
                attrs = parse_attrs_header(response["headers"]["x-amz-meta-s3cmd-attrs"])
                response["s3cmd-attrs"] = attrs
            debug("Response: %s" % response)
        except ParameterError, e:
            raise
        except OSError, e:
            raise
        except (IOError, Exception), e:
            if self.config.progress_meter:
                progress.done("failed")
            if hasattr(e, 'errno') and e.errno != errno.EPIPE:
                raise
            # close the connection and re-establish
            conn.counter = ConnMan.conn_max_counter
            ConnMan.put(conn)

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
            info("Redirected to: %s" % (redir_hostname))
            return self.recv_file(request, stream, labels)

        if response["status"] == 400:
            return self._http_400_handler(request, response, self.recv_file, request, stream, labels)
        if response["status"] == 403:
            return self._http_403_handler(request, response, self.recv_file, request, stream, labels)
        if response["status"] == 405: # Method Not Allowed.  Don't retry.
            raise S3Error(response)

        if response["status"] < 200 or response["status"] > 299:
            raise S3Error(response)

        if start_position == 0:
            # Only compute MD5 on the fly if we're downloading from beginning
            # Otherwise we'd get a nonsense.
            md5_hash = md5()
        size_left = long(response["headers"]["content-length"])
        size_total = start_position + size_left
        current_position = start_position

        if self.config.progress_meter:
            progress.total_size = size_total
            progress.initial_position = current_position
            progress.current_position = current_position

        try:
            # Fix for issue #432. Even when content size is 0, httplib expect the response to be read.
            if size_left == 0:
                data = http_response.read(1)
                # It is not supposed to be some data returned in that case
                assert(len(data) == 0)
            while (current_position < size_total):
                this_chunk = size_left > self.config.recv_chunk and self.config.recv_chunk or size_left

                if self.config.limitrate > 0:
                    start_time = time.time()

                data = http_response.read(this_chunk)
                if len(data) == 0:
                    raise S3ResponseError("EOF from S3!")

                #throttle
                if self.config.limitrate > 0:
                    real_duration = time.time() - start_time
                    expected_duration = float(this_chunk)/self.config.limitrate
                    if expected_duration > real_duration:
                        time.sleep(expected_duration - real_duration)

                stream.write(data)
                if start_position == 0:
                    md5_hash.update(data)
                current_position += len(data)
                ## Call progress meter from here...
                if self.config.progress_meter:
                    progress.update(delta_position = len(data))
            ConnMan.put(conn)
        except OSError:
            raise
        except (IOError, Exception), e:
            if self.config.progress_meter:
                progress.done("failed")
            if hasattr(e, 'errno') and e.errno != errno.EPIPE:
                raise
            # close the connection and re-establish
            conn.counter = ConnMan.conn_max_counter
            ConnMan.put(conn)

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

        md5_from_s3 = response["headers"]["etag"].strip('"')
        if not 'x-amz-meta-s3tools-gpgenc' in response["headers"]:
            # we can't trust our stored md5 because we
            # encrypted the file after calculating it but before
            # uploading it.
            try:
                md5_from_s3 = response["s3cmd-attrs"]["md5"]
            except KeyError:
                pass
        # we must have something to compare against to bother with the calculation
        if '-' not in md5_from_s3:
            if start_position == 0:
                # Only compute MD5 on the fly if we were downloading from the beginning
                response["md5"] = md5_hash.hexdigest()
            else:
                # Otherwise try to compute MD5 of the output file
                try:
                    response["md5"] = hash_file_md5(filename)
                except IOError, e:
                    if e.errno != errno.ENOENT:
                        warning("Unable to open file: %s: %s" % (filename, e))
                    warning("Unable to verify MD5. Assume it matches.")

        response["md5match"] = response.get("md5") == md5_from_s3
        response["elapsed"] = timestamp_end - timestamp_start
        response["size"] = current_position
        response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)
        if response["size"] != start_position + long(response["headers"]["content-length"]):
            warning("Reported size (%s) does not match received size (%s)" % (
                start_position + long(response["headers"]["content-length"]), response["size"]))
        debug("ReceiveFile: Computed MD5 = %s" % response.get("md5"))
        # avoid ETags from multipart uploads that aren't the real md5
        if '-' not in md5_from_s3 and not response["md5match"]:
            warning("MD5 signatures do not match: computed=%s, received=%s" % (
                response.get("md5"), md5_from_s3))
        return response
__all__.append("S3")

def parse_attrs_header(attrs_header):
    attrs = {}
    for attr in attrs_header.split("/"):
        key, val = attr.split(":")
        attrs[key] = val
    return attrs

def compute_content_md5(body):
    m = md5(body)
    base64md5 = base64.encodestring(m.digest())
    if base64md5[-1] == '\n':
        base64md5 = base64md5[0:-1]
    return base64md5
# vim:et:ts=4:sts=4:ai
