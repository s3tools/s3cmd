# -*- coding: utf-8 -*-

## --------------------------------------------------------------------
## Amazon S3 manager
##
## Authors   : Michal Ludvig <michal@logix.cz> (https://www.logix.cz/michal)
##             Florent Viard <florent@sodria.com> (https://www.sodria.com)
## Copyright : TGRMN Software, Sodria SAS and contributors
## License   : GPL Version 2
## Website   : https://s3tools.org
## --------------------------------------------------------------------

from __future__ import absolute_import, division

import sys
import os
import time
import errno
import mimetypes
import io
import pprint
from xml.sax import saxutils
from socket import timeout as SocketTimeoutException
from logging import debug, info, warning, error
from stat import ST_SIZE, ST_MODE, S_ISDIR, S_ISREG
try:
    # python 3 support
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import select

from .BaseUtils import (getListFromXml, getTextFromXml, getRootTagName,
                        decode_from_s3, encode_to_s3, md5, s3_quote)
from .Utils import (convertHeaderTupleListToDict, unicodise,
                    deunicodise, check_bucket_name,
                    check_bucket_name_dns_support, getHostnameFromBucket)
from .SortedDict import SortedDict
from .AccessLog import AccessLog
from .ACL import ACL, GranteeLogDelivery
from .BidirMap import BidirMap
from .Config import Config
from .Exceptions import *
from .MultiPart import MultiPartUpload
from .S3Uri import S3Uri
from .ConnMan import ConnMan
from .Crypto import (sign_request_v2, sign_request_v4, checksum_sha256_file,
                     checksum_sha256_buffer, generate_content_md5,
                     hash_file_md5, calculateChecksum, format_param_str)

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

except (ImportError, OSError) as e:
    error_str = str(e)
    if 'magic' in error_str:
        magic_message = "Module python-magic is not available."
    else:
        magic_message = "Module python-magic can't be used (%s)." % error_str
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


EXPECT_CONTINUE_TIMEOUT = 2
SIZE_1MB = 1024 * 1024

__all__ = []

class S3Request(object):
    region_map = {}
    ## S3 sometimes sends HTTP-301, HTTP-307 response
    redir_map = {}

    def __init__(self, s3, method_string, resource, headers, body, params = None):
        self.s3 = s3
        self.headers = SortedDict(headers or {}, ignore_case = True)
        if len(self.s3.config.access_token)>0:
            self.s3.config.role_refresh()
            self.headers['x-amz-security-token']=self.s3.config.access_token
        self.resource = resource
        self.method_string = method_string
        self.params = params or {}
        self.body = body
        self.requester_pays()

    def requester_pays(self):
        if self.s3.config.requester_pays and self.method_string in ("GET", "POST", "PUT", "HEAD"):
            self.headers['x-amz-request-payer'] = 'requester'

    def update_timestamp(self):
        if "date" in self.headers:
            del(self.headers["date"])
        self.headers["x-amz-date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

    def use_signature_v2(self):
        if self.s3.endpoint_requires_signature_v4:
            return False

        if self.s3.config.signature_v2 or self.s3.fallback_to_signature_v2:
            return True

        return False

    def sign(self):
        bucket_name = self.resource.get('bucket')

        if self.use_signature_v2():
            debug("Using signature v2")
            if bucket_name:
                resource_uri = "/%s%s" % (bucket_name, self.resource['uri'])
            else:
                resource_uri = self.resource['uri']

            self.headers = sign_request_v2(self.method_string, resource_uri, self.params, self.headers)
        else:
            debug("Using signature v4")
            hostname = self.s3.get_hostname(self.resource['bucket'])

            ## Default to bucket part of DNS.
            ## If bucket is not part of DNS assume path style to complete the request.
            ## Like for format_uri, take care that redirection could be to base path
            if bucket_name and (
                (bucket_name in S3Request.redir_map
                 and not S3Request.redir_map.get(bucket_name, '').startswith("%s."% bucket_name))
                or (bucket_name not in S3Request.redir_map
                 and not check_bucket_name_dns_support(Config().host_bucket, bucket_name))
            ):
                resource_uri = "/%s%s" % (bucket_name, self.resource['uri'])
            else:
                resource_uri = self.resource['uri']

            bucket_region = S3Request.region_map.get(self.resource['bucket'], Config().bucket_location)
            ## Sign the data.
            self.headers = sign_request_v4(self.method_string, hostname, resource_uri, self.params,
                                          bucket_region, self.headers, self.body)

    def get_triplet(self):
        self.update_timestamp()
        self.sign()

        resource = dict(self.resource)  ## take a copy

        # URL Encode the uri for the http request
        resource['uri'] = s3_quote(resource['uri'], quote_backslashes=False, unicode_output=True)
        # Get the final uri by adding the uri parameters
        resource['uri'] += format_param_str(self.params)
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
        UNDEFINED = 0x0000,
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

    def __init__(self, config):
        self.config = config
        self.fallback_to_signature_v2 = False
        self.endpoint_requires_signature_v4 = False
        self.expect_continue_not_supported = False

    def storage_class(self):
        # Note - you cannot specify GLACIER here
        # https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html
        cls = 'STANDARD'
        if self.config.storage_class != "":
            return self.config.storage_class
        if self.config.reduced_redundancy:
            cls = 'REDUCED_REDUNDANCY'
        return cls

    def get_hostname(self, bucket):
        if bucket and bucket in S3Request.redir_map:
            host = S3Request.redir_map[bucket]
        elif bucket and check_bucket_name_dns_support(self.config.host_bucket, bucket):
            host = getHostnameFromBucket(bucket)
        else:
            host = self.config.host_base.lower()
        # The following hack is needed because it looks like that some servers
        # are not respecting the HTTP spec and so will fail the signature check
        # if the port is specified in the "Host" header for default ports.
        # STUPIDIEST THING EVER FOR A SERVER...
        # See: https://github.com/minio/minio/issues/9169
        if self.config.use_https:
            if host.endswith(':443'):
                host = host[:-4]
        elif host.endswith(':80'):
            host = host[:-3]

        debug('get_hostname(%s): %s' % (bucket, host))
        return host

    def set_hostname(self, bucket, redir_hostname):
        S3Request.redir_map[bucket] = redir_hostname.lower()

    def format_uri(self, resource, base_path=None):
        bucket_name = resource.get('bucket')
        if bucket_name and (
             (bucket_name in S3Request.redir_map
              and not S3Request.redir_map.get(bucket_name, '').startswith("%s."% bucket_name))
             or (bucket_name not in S3Request.redir_map
                and not check_bucket_name_dns_support(self.config.host_bucket, bucket_name))
            ):
                uri = "/%s%s" % (s3_quote(bucket_name, quote_backslashes=False,
                                          unicode_output=True),
                                 resource['uri'])
        else:
            uri = resource['uri']
        if base_path:
            uri = "%s%s" % (base_path, uri)
        if self.config.proxy_host != "" and not self.config.use_https:
            uri = "http://%s%s" % (self.get_hostname(bucket_name), uri)
        debug('format_uri(): ' + uri)
        return uri

    ## Commands / Actions
    def list_all_buckets(self):
        request = self.create_request("LIST_ALL_BUCKETS")
        response = self.send_request(request)
        response["list"] = getListFromXml(response["data"], "Bucket")
        return response

    def bucket_list(self, bucket, prefix = None, recursive = None, uri_params = None, limit = -1):
        item_list = []
        prefixes = []
        for truncated, dirs, objects in self.bucket_list_streaming(bucket, prefix, recursive, uri_params, limit):
            item_list.extend(objects)
            prefixes.extend(dirs)

        response = {}
        response['list'] = item_list
        response['common_prefixes'] = prefixes
        response['truncated'] = truncated
        return response

    def bucket_list_streaming(self, bucket, prefix = None, recursive = None, uri_params = None, limit = -1):
        """ Generator that produces <dir_list>, <object_list> pairs of groups of content of a specified bucket. """
        def _list_truncated(data):
            ## <IsTruncated> can either be "true" or "false" or be missing completely
            is_truncated = getTextFromXml(data, ".//IsTruncated") or "false"
            return is_truncated.lower() != "false"

        def _get_contents(data):
            return getListFromXml(data, "Contents")

        def _get_common_prefixes(data):
            return getListFromXml(data, "CommonPrefixes")

        def _get_next_marker(data, current_elts, key):
            return getTextFromXml(response["data"], "NextMarker") or current_elts[-1][key]

        uri_params = uri_params and uri_params.copy() or {}
        truncated = True
        prefixes = []

        num_objects = 0
        num_prefixes = 0
        max_keys = limit
        while truncated:
            response = self.bucket_list_noparse(bucket, prefix, recursive,
                                                uri_params, max_keys)
            current_list = _get_contents(response["data"])
            current_prefixes = _get_common_prefixes(response["data"])
            num_objects += len(current_list)
            num_prefixes += len(current_prefixes)
            if limit > num_objects + num_prefixes:
                max_keys = limit - (num_objects + num_prefixes)
            truncated = _list_truncated(response["data"])
            if truncated:
                if limit == -1 or num_objects + num_prefixes < limit:
                    if current_list:
                        uri_params['marker'] = \
                            _get_next_marker(response["data"], current_list, "Key")
                    elif current_prefixes:
                        uri_params['marker'] = \
                            _get_next_marker(response["data"], current_prefixes, "Prefix")
                    else:
                        # Unexpectedly, the server lied, and so the previous
                        # response was not truncated. So, no new key to get.
                        yield False, current_prefixes, current_list
                        break
                    debug("Listing continues after '%s'" % uri_params['marker'])
                else:
                    yield truncated, current_prefixes, current_list
                    break

            yield truncated, current_prefixes, current_list

    def bucket_list_noparse(self, bucket, prefix = None, recursive = None, uri_params = None, max_keys = -1):
        if uri_params is None:
            uri_params = {}
        if prefix:
            uri_params['prefix'] = prefix
        if not self.config.recursive and not recursive:
            uri_params['delimiter'] = "/"
        if max_keys != -1:
            uri_params['max-keys'] = str(max_keys)
        if self.config.list_allow_unordered:
            uri_params['allow-unordered'] = "true"
        request = self.create_request("BUCKET_LIST", bucket = bucket, uri_params = uri_params)
        response = self.send_request(request)
        #debug(response)
        return response

    def bucket_create(self, bucket, bucket_location = None, extra_headers = None):
        headers = SortedDict(ignore_case = True)
        if extra_headers:
            headers.update(extra_headers)

        body = ""
        if bucket_location and bucket_location.strip().upper() != "US" and bucket_location.strip().lower() != "us-east-1":
            bucket_location = bucket_location.strip()
            if bucket_location.upper() == "EU":
                bucket_location = bucket_location.upper()
            body  = "<CreateBucketConfiguration><LocationConstraint>"
            body += bucket_location
            body += "</LocationConstraint></CreateBucketConfiguration>"
            debug("bucket_location: " + body)
            check_bucket_name(bucket, dns_strict = True)
        else:
            check_bucket_name(bucket, dns_strict = False)
        if self.config.acl_public:
            headers["x-amz-acl"] = "public-read"
            # AWS suddenly changed the default "ownership" control value mid 2023.
            # ACL are disabled by default, so obviously the bucket can't be public.
            # See: https://aws.amazon.com/fr/blogs/aws/heads-up-amazon-s3-security-changes-are-coming-in-april-of-2023/
            # To be noted: "Block Public Access" flags should also be disabled after the bucket creation to be able to set a "public" acl for an object.
            headers["x-amz-object-ownership"] = 'ObjectWriter'

        request = self.create_request("BUCKET_CREATE", bucket = bucket, headers = headers, body = body)
        response = self.send_request(request)
        return response

    def bucket_delete(self, bucket):
        request = self.create_request("BUCKET_DELETE", bucket = bucket)
        response = self.send_request(request)
        return response

    def get_bucket_location(self, uri, force_us_default=False):
        bucket = uri.bucket()
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'location': None})

        saved_redir_map = S3Request.redir_map.get(bucket, '')
        saved_region_map = S3Request.region_map.get(bucket, '')

        try:
            if force_us_default and not (saved_redir_map and saved_region_map):
                S3Request.redir_map[bucket] = self.config.host_base
                S3Request.region_map[bucket] = 'us-east-1'

            response = self.send_request(request)
        finally:
            if bucket in saved_redir_map:
                S3Request.redir_map[bucket] = saved_redir_map
            elif bucket in S3Request.redir_map:
                del S3Request.redir_map[bucket]

            if bucket in saved_region_map:
                S3Request.region_map[bucket] = saved_region_map
            elif bucket in S3Request.region_map:
                del S3Request.region_map[bucket]


        location = getTextFromXml(response['data'], "LocationConstraint")
        if not location or location in [ "", "US" ]:
            location = "us-east-1"
        elif location == "EU":
            location = "eu-west-1"
        return location

    def get_bucket_requester_pays(self, uri):
        request = self.create_request("BUCKET_LIST", bucket=uri.bucket(),
                                      uri_params={'requestPayment': None})
        response = self.send_request(request)
        resp_data = response.get('data', '')
        if resp_data:
            payer = getTextFromXml(resp_data, "Payer")
        else:
            payer = None
        return payer

    def set_bucket_ownership(self, uri, ownership):
        headers = SortedDict(ignore_case=True)
        body = '<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
                    '<Rule>' \
                        '<ObjectOwnership>%s</ObjectOwnership>' \
                    '</Rule>' \
                '</OwnershipControls>'
        body = body % ownership
        debug(u"set_bucket_ownership(%s)" % body)
        headers['content-md5'] = generate_content_md5(body)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers = headers, body = body,
                                      uri_params = {'ownershipControls': None})
        response = self.send_request(request)
        return response

    def get_bucket_ownership(self, uri):
        request = self.create_request("BUCKET_LIST", bucket=uri.bucket(),
                                      uri_params={'ownershipControls': None})
        response = self.send_request(request)
        resp_data = response.get('data', '')
        if resp_data:
            ownership = getTextFromXml(resp_data, ".//Rule//ObjectOwnership")
        else:
            ownership = None
        return ownership

    def set_bucket_public_access_block(self, uri, flags):
        headers = SortedDict(ignore_case=True)

        body = '<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        for tag in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'):
            val = flags.get(tag, False) and "true" or "false"
            body += '<%s>%s</%s>' % (tag, val, tag)
        body += '</PublicAccessBlockConfiguration>'

        debug(u"set_bucket_public_access_block(%s)" % body)
        headers['content-md5'] = generate_content_md5(body)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers = headers, body = body,
                                      uri_params = {'publicAccessBlock': None})
        response = self.send_request(request)
        return response

    def get_bucket_public_access_block(self, uri):
        request = self.create_request("BUCKET_LIST", bucket=uri.bucket(),
                                      uri_params={'publicAccessBlock': None})
        response = self.send_request(request)
        resp_data = response.get('data', '')
        if resp_data:
            flags = {
                "BlockPublicAcls": getTextFromXml(resp_data, "BlockPublicAcls") == "true",
                "IgnorePublicAcls": getTextFromXml(resp_data, "IgnorePublicAcls") == "true",
                "BlockPublicPolicy": getTextFromXml(resp_data, "BlockPublicPolicy") == "true",
                "RestrictPublicBuckets": getTextFromXml(resp_data, "RestrictPublicBuckets") == "true",
            }
        else:
            flags = {}
        return flags

    def bucket_info(self, uri):
        response = {}
        response['bucket-location'] = self.get_bucket_location(uri)

        for key, func in (('requester-pays', self.get_bucket_requester_pays),
                          ('versioning', self.get_versioning),
                          ('ownership', self.get_bucket_ownership)):
            try:
                response[key] = func(uri)
            except S3Error as e:
                response[key] = None

        try:
            response['public-access-block'] = self.get_bucket_public_access_block(uri)
        except S3Error as e:
            response['public-access-block'] = {}

        return response

    def website_info(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_LIST", bucket = bucket,
                                      uri_params = {'website': None})
        try:
            response = self.send_request(request)
            response['index_document'] = getTextFromXml(response['data'], ".//IndexDocument//Suffix")
            response['error_document'] = getTextFromXml(response['data'], ".//ErrorDocument//Key")
            response['website_endpoint'] = self.config.website_endpoint % {
                "bucket" : uri.bucket(),
                "location" : self.get_bucket_location(uri)}
            return response
        except S3Error as e:
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

        request = self.create_request("BUCKET_CREATE", bucket = bucket, body = body,
                                      uri_params = {'website': None})
        response = self.send_request(request)
        debug("Received response '%s'" % (response))

        return response

    def website_delete(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_DELETE", bucket = bucket,
                                      uri_params = {'website': None})
        response = self.send_request(request)
        debug("Received response '%s'" % (response))

        if response['status'] != 204:
            raise S3ResponseError("Expected status 204: %s" % response)

        return response

    def expiration_info(self, uri, bucket_location = None):
        bucket = uri.bucket()

        request = self.create_request("BUCKET_LIST", bucket=bucket,
                                      uri_params={'lifecycle': None})
        try:
            response = self.send_request(request)
        except S3Error as e:
            if e.status == 404:
                debug("Could not get /?lifecycle - lifecycle probably not "
                      "configured for this bucket")
                return None
            elif e.status == 501:
                debug("Could not get /?lifecycle - lifecycle support not "
                      "implemented by the server")
                return None
            raise

        root_tag_name = getRootTagName(response['data'])
        if root_tag_name != "LifecycleConfiguration":
            debug("Could not get /?lifecycle - unexpected xml response: "
                  "%s", root_tag_name)
            return None
        response['prefix'] = getTextFromXml(response['data'],
                                            ".//Rule//Prefix")
        response['date'] = getTextFromXml(response['data'],
                                          ".//Rule//Expiration//Date")
        response['days'] = getTextFromXml(response['data'],
                                          ".//Rule//Expiration//Days")
        return response

    def expiration_set(self, uri, bucket_location = None):
        if self.config.expiry_date and self.config.expiry_days:
             raise ParameterError("Expect either --expiry-day or --expiry-date")
        if not (self.config.expiry_date or self.config.expiry_days):
             if self.config.expiry_prefix:
                 raise ParameterError("Expect either --expiry-day or --expiry-date")
             debug("del bucket lifecycle")
             bucket = uri.bucket()
             request = self.create_request("BUCKET_DELETE", bucket = bucket,
                                           uri_params = {'lifecycle': None})
        else:
             request = self._expiration_set(uri)
        response = self.send_request(request)
        debug("Received response '%s'" % (response))
        return response

    def _expiration_set(self, uri):
        debug("put bucket lifecycle")
        body = '<LifecycleConfiguration>'
        body += '  <Rule>'
        body += '    <Filter>'
        body += '      <Prefix>%s</Prefix>' % self.config.expiry_prefix
        body += '    </Filter>'
        body += '    <Status>Enabled</Status>'
        body += '    <Expiration>'
        if self.config.expiry_date:
            body += '      <Date>%s</Date>' % self.config.expiry_date
        elif self.config.expiry_days:
            body += '      <Days>%s</Days>' % self.config.expiry_days
        body += '    </Expiration>'
        body += '  </Rule>'
        body += '</LifecycleConfiguration>'

        headers = SortedDict(ignore_case = True)
        headers['content-md5'] = generate_content_md5(body)
        bucket = uri.bucket()
        request =  self.create_request("BUCKET_CREATE", bucket = bucket,
                                       headers = headers, body = body,
                                       uri_params = {'lifecycle': None})
        return (request)

    def _guess_content_type(self, filename):
        content_type = self.config.default_mime_type
        content_charset = None

        if filename == "-" and not self.config.default_mime_type:
            raise ParameterError("You must specify --mime-type or --default-mime-type for files uploaded from stdin.")

        if self.config.guess_mime_type:
            if self.config.follow_symlinks:
                filename = unicodise(os.path.realpath(deunicodise(filename)))
            if self.config.use_mime_magic:
                (content_type, content_charset) = mime_magic(filename)
            else:
                (content_type, content_charset) = mimetypes.guess_type(filename)

        if not content_type:
            content_type = self.config.default_mime_type
        return (content_type, content_charset)

    def stdin_content_type(self):
        content_type = self.config.mime_type
        if not content_type:
            content_type = self.config.default_mime_type

        content_type += "; charset=" + self.config.encoding.upper()
        return content_type

    def content_type(self, filename=None, is_dir=False):
        # explicit command line argument always wins
        content_type = self.config.mime_type
        content_charset = None

        if filename == u'-':
            return self.stdin_content_type()

        if is_dir:
            content_type = 'application/x-directory'
        elif not content_type:
            (content_type, content_charset) = self._guess_content_type(filename)

        ## add charset to content type
        if not content_charset:
            content_charset = self.config.encoding.upper()
        if self.add_encoding(filename, content_type) and content_charset is not None:
            content_type = content_type + "; charset=" + content_charset

        return content_type

    def add_encoding(self, filename, content_type):
        if not filename:
            return False
        if 'charset=' in content_type:
           return False
        exts = self.config.add_encoding_exts.split(',')
        if exts[0]=='':
            return False
        parts = filename.rsplit('.', 1)
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

        try:
            is_dir = False
            size = 0
            if filename == "-":
                is_stream = True
                src_stream = io.open(sys.stdin.fileno(), mode='rb', closefd=False)
                src_stream.stream_name = u'<stdin>'

            else:
                is_stream = False
                filename_bytes = deunicodise(filename)

                stat = os.stat(filename_bytes)
                mode = stat[ST_MODE]

                if S_ISDIR(mode):
                    is_dir = True
                    # Dirs are represented as empty objects on S3
                    src_stream = io.BytesIO(b'')
                elif not S_ISREG(mode):
                    raise InvalidFileError(u"Not a regular file")
                else:
                    # Standard normal file
                    src_stream = io.open(filename_bytes, mode='rb')
                    size = stat[ST_SIZE]
                src_stream.stream_name = filename
        except (IOError, OSError) as e:
            raise InvalidFileError(u"%s" % e.strerror)

        headers = SortedDict(ignore_case=True)
        if extra_headers:
            headers.update(extra_headers)

        ## Set server side encryption
        if self.config.server_side_encryption:
            headers["x-amz-server-side-encryption"] = "AES256"

        ## Set kms headers
        if self.config.kms_key:
            headers['x-amz-server-side-encryption'] = 'aws:kms'
            headers['x-amz-server-side-encryption-aws-kms-key-id'] = self.config.kms_key

        ## MIME-type handling
        headers["content-type"] = self.content_type(filename=filename, is_dir=is_dir)

        ## Other Amazon S3 attributes
        if self.config.acl_public:
            headers["x-amz-acl"] = "public-read"
        headers["x-amz-storage-class"] = self.storage_class()

        ## Multipart decision
        multipart = False
        if not self.config.enable_multipart and is_stream:
            raise ParameterError("Multi-part upload is required to upload from stdin")
        if self.config.enable_multipart:
            if size > self.config.multipart_chunk_size_mb * SIZE_1MB or is_stream:
                multipart = True
                if size > self.config.multipart_max_chunks * self.config.multipart_chunk_size_mb * SIZE_1MB:
                    raise ParameterError("Chunk size %d MB results in more than %d chunks. Please increase --multipart-chunk-size-mb" % \
                          (self.config.multipart_chunk_size_mb, self.config.multipart_max_chunks))
        if multipart:
            # Multipart requests are quite different... drop here
            return self.send_file_multipart(src_stream, headers, uri, size, extra_label)

        ## Not multipart...
        if self.config.put_continue:
            # Note, if input was stdin, we would be performing multipart upload.
            # So this will always work as long as the file already uploaded was
            # not uploaded via MultiUpload, in which case its ETag will not be
            # an md5.
            try:
                info = self.object_info(uri)
            except Exception:
                info = None

            if info is not None:
                remote_size = int(info['headers']['content-length'])
                remote_checksum = info['headers']['etag'].strip('"\'')
                if size == remote_size:
                    checksum = calculateChecksum('', src_stream, 0, size, self.config.send_chunk)
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
        response = self.send_file(request, src_stream, labels)
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
        return self.object_batch_delete_uri_strs(uris)

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
        headers = SortedDict({'content-md5': generate_content_md5(request_body),
                   'content-type': 'application/xml'}, ignore_case=True)
        request = self.create_request("BATCH_DELETE", bucket = bucket,
                                      headers = headers, body = request_body,
                                      uri_params = {'delete': None})
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
        if self.config.restore_days < 1:
            raise ParameterError("You must restore a file for 1 or more days")
        if self.config.restore_priority not in ['Standard', 'Expedited', 'Bulk']:
            raise ParameterError("Valid restoration priorities: bulk, standard, expedited")
        body =   '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += ('  <Days>%s</Days>' % self.config.restore_days)
        body +=  '  <GlacierJobParameters>'
        body += ('    <Tier>%s</Tier>' % self.config.restore_priority)
        body +=  '  </GlacierJobParameters>'
        body +=  '</RestoreRequest>'
        request = self.create_request("OBJECT_POST", uri = uri, body = body,
                                      uri_params = {'restore': None})
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
            'connection',
            'etag',
            'server',
            'x-amz-id-2',
            'x-amz-request-id',
            # Cloudflare's R2 header we don't want to send
            'cf-ray',
            # Other headers that are not copying by a direct copy
            'x-amz-storage-class',
            ## We should probably also add server-side encryption headers
        ]

        for h in to_remove + self.config.remove_headers:
            if h.lower() in headers:
                del headers[h.lower()]
        return headers

    def object_copy(self, src_uri, dst_uri, extra_headers=None,
                    src_size=None, extra_label="", replace_meta=False):
        """Remote copy an object and eventually set metadata

        Note: A little memo description of the nightmare for performance here:
        ** FOR AWS, 2 cases:
        - COPY will copy the metadata of the source to dest, but you can't
        modify them. Any additional header will be ignored anyway.
        - REPLACE will set the additional metadata headers that are provided
        but will not copy any of the source headers.
        So, to add to existing meta during copy, you have to do an object_info
        to get original source headers, then modify, then use REPLACE for the
        copy operation.

        ** For Minio and maybe other implementations:
        - if additional headers are sent, they will be set to the destination
        on top of source original meta in all cases COPY and REPLACE.
        It is a nice behavior except that it is different of the aws one.

        As it was still too easy, there is another catch:
        In all cases, for multipart copies, metadata data are never copied
        from the source.
        """
        if src_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % src_uri.type)
        if dst_uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % dst_uri.type)
        if self.config.acl_public is None:
            try:
                acl = self.get_acl(src_uri)
            except S3Error as exc:
                # Ignore the exception and don't fail the copy
                # if the server doesn't support setting ACLs
                if exc.status != 501:
                    raise exc
                acl = None

        multipart = False
        headers = None

        if extra_headers or self.config.mime_type:
            # Force replace, that will force getting meta with object_info()
            replace_meta = True

        if replace_meta:
            src_info = self.object_info(src_uri)
            headers = src_info['headers']
            src_size = int(headers["content-length"])

        if self.config.enable_multipart:
            # Get size of remote source only if multipart is enabled and that no
            # size info was provided
            src_headers = headers
            if src_size is None:
                src_info = self.object_info(src_uri)
                src_headers = src_info['headers']
                src_size = int(src_headers["content-length"])

            # If we are over the grand maximum size for a normal copy/modify
            # (> 5GB) go nuclear and use multipart copy as the only option to
            # modify an object.
            # Reason is an aws s3 design bug. See:
            # https://github.com/aws/aws-sdk-java/issues/367
            if src_uri is dst_uri:
                # optimisation in the case of modify
                threshold = MultiPartUpload.MAX_CHUNK_SIZE_MB * SIZE_1MB
            else:
                threshold = self.config.multipart_copy_chunk_size_mb * SIZE_1MB

            if src_size > threshold:
                # Sadly, s3 has a bad logic as metadata will not be copied for
                # multipart copy unlike what is done for direct copies.
                # TODO: Optimize by reusing the object_info request done
                # earlier earlier at fetch remote stage, and preserve headers.
                if src_headers is None:
                    src_info = self.object_info(src_uri)
                    src_headers = src_info['headers']
                    src_size = int(src_headers["content-length"])
                headers = src_headers
                multipart = True

        if headers:
            self._sanitize_headers(headers)
            headers = SortedDict(headers, ignore_case=True)
        else:
            headers = SortedDict(ignore_case=True)

        # Following meta data are updated even in COPY by aws
        if self.config.acl_public:
            headers["x-amz-acl"] = "public-read"

        headers["x-amz-storage-class"] = self.storage_class()

        ## Set server side encryption
        if self.config.server_side_encryption:
            headers["x-amz-server-side-encryption"] = "AES256"

        ## Set kms headers
        if self.config.kms_key:
            headers['x-amz-server-side-encryption'] = 'aws:kms'
            headers['x-amz-server-side-encryption-aws-kms-key-id'] = \
                self.config.kms_key

        # Following meta data are not updated in simple COPY by aws.
        if extra_headers:
            headers.update(extra_headers)

        if self.config.mime_type:
            headers["content-type"] = self.config.mime_type

        # "COPY" or "REPLACE"
        if not replace_meta:
            headers['x-amz-metadata-directive'] = "COPY"
        else:
            headers['x-amz-metadata-directive'] = "REPLACE"

        if multipart:
            # Multipart decision. Only do multipart copy for remote s3 files
            # bigger than the multipart copy threshold.

            # Multipart requests are quite different... delegate
            response = self.copy_file_multipart(src_uri, dst_uri, src_size,
                                                headers, extra_label)
        else:
            # Not multipart... direct request
            headers['x-amz-copy-source'] = s3_quote(
                "/%s/%s" % (src_uri.bucket(), src_uri.object()),
                quote_backslashes=False, unicode_output=True)

            request = self.create_request("OBJECT_PUT", uri=dst_uri,
                                          headers=headers)
            response = self.send_request(request)

        if response["data"] and getRootTagName(response["data"]) == "Error":
            # http://doc.s3.amazonaws.com/proposals/copy.html
            # Error during copy, status will be 200, so force error code 500
            response["status"] = 500
            error("Server error during the COPY operation. Overwrite response "
                  "status to 500")
            raise S3Error(response)

        if self.config.acl_public is None and acl:
            try:
                self.set_acl(dst_uri, acl)
            except S3Error as exc:
                # Ignore the exception and don't fail the copy
                # if the server doesn't support setting ACLs
                if exc.status != 501:
                    raise exc
        return response

    def object_modify(self, src_uri, dst_uri, extra_headers=None,
                      src_size=None, extra_label=""):
        # dst_uri = src_uri Will optimize by using multipart just in worst case
        return self.object_copy(src_uri, src_uri, extra_headers, src_size,
                                extra_label, replace_meta=True)

    def object_move(self, src_uri, dst_uri, extra_headers=None,
                    src_size=None, extra_label=""):
        response_copy = self.object_copy(src_uri, dst_uri, extra_headers,
                                         src_size, extra_label)
        debug("Object %s copied to %s" % (src_uri, dst_uri))
        if not response_copy["data"] \
           or getRootTagName(response_copy["data"]) \
           in ["CopyObjectResult", "CompleteMultipartUploadResult"]:
            self.object_delete(src_uri)
            debug("Object '%s' deleted", src_uri)
        else:
            warning("Object '%s' NOT deleted because of an unexpected "
                    "response data content.", src_uri)
        return response_copy

    def object_info(self, uri):
        request = self.create_request("OBJECT_HEAD", uri=uri)
        try:
            response = self.send_request(request)
        except S3Error as exc:
            # A HEAD request will not have body, even in the case of an error
            # so we can't get the usual XML error content.
            # Add fake similar content in such a case
            if exc.status == 404 and not exc.code:
                exc.code = 'NoSuchKey'
                exc.message = 'The specified key does not exist.'
                exc.resource = uri
            raise exc
        return response

    def get_acl(self, uri):
        if uri.has_object():
            request = self.create_request("OBJECT_GET", uri=uri,
                                          uri_params={'acl': None})
        else:
            request = self.create_request("BUCKET_LIST", bucket=uri.bucket(),
                                          uri_params={'acl': None})

        response = self.send_request(request)
        acl = ACL(response['data'])
        return acl

    def set_acl(self, uri, acl):
        body = u"%s"% acl
        debug(u"set_acl(%s): acl-xml: %s" % (uri, body))

        headers = SortedDict({'content-type': 'application/xml'}, ignore_case = True)
        if uri.has_object():
            request = self.create_request("OBJECT_PUT", uri = uri,
                                          headers = headers, body = body,
                                          uri_params = {'acl': None})
        else:
            request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(),
                                          headers = headers, body = body,
                                          uri_params = {'acl': None})

        response = self.send_request(request)
        return response

    def set_versioning(self, uri, enabled):
        headers = SortedDict(ignore_case = True)
        status = "Enabled" if enabled is True else "Suspended"
        body = '<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += '<Status>%s</Status>' % status
        body += '</VersioningConfiguration>'
        debug(u"set_versioning(%s)" % body)
        headers['content-md5'] = generate_content_md5(body)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers = headers, body = body,
                                      uri_params = {'versioning': None})
        response = self.send_request(request)
        return response

    def get_versioning(self, uri):
        request = self.create_request("BUCKET_LIST", uri = uri,
                                      uri_params = {'versioning': None})
        response = self.send_request(request)

        return getTextFromXml(response['data'], "Status")

    def get_policy(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'policy': None})
        response = self.send_request(request)
        return decode_from_s3(response['data'])

    def set_object_legal_hold(self, uri, legal_hold_status):
        body = '<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += '<Status>%s</Status>' % legal_hold_status
        body += '</LegalHold>'
        headers = SortedDict(ignore_case = True)
        headers['content-type'] = 'application/xml'
        headers['content-md5'] = generate_content_md5(body)
        request = self.create_request("OBJECT_PUT", uri = uri,
                                      headers = headers, body = body,
                                      uri_params = {'legal-hold': None})
        response = self.send_request(request)
        return response

    def set_object_retention(self, uri, mode, retain_until_date):
        body = '<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += '<Mode>%s</Mode>' % mode
        body += '<RetainUntilDate>%s</RetainUntilDate>' % retain_until_date
        body += '</Retention>'
        headers = SortedDict(ignore_case = True)
        headers['content-type'] = 'application/xml'
        headers['content-md5'] = generate_content_md5(body)
        request = self.create_request("OBJECT_PUT", uri = uri,
                                      headers = headers, body = body,
                                      uri_params = {'retention': None})
        response = self.send_request(request)
        return response

    def set_policy(self, uri, policy):
        headers = SortedDict(ignore_case = True)
        # TODO check policy is proper json string
        headers['content-type'] = 'application/json'
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers=headers, body = policy,
                                      uri_params = {'policy': None})
        response = self.send_request(request)
        return response

    def delete_policy(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri,
                                      uri_params = {'policy': None})
        debug(u"delete_policy(%s)" % uri)
        response = self.send_request(request)
        return response

    def get_cors(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'cors': None})
        response = self.send_request(request)
        return decode_from_s3(response['data'])

    def set_cors(self, uri, cors):
        headers = SortedDict(ignore_case = True)
        # TODO check cors is proper json string
        headers['content-type'] = 'application/xml'
        headers['content-md5'] = generate_content_md5(cors)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers=headers, body = cors,
                                      uri_params = {'cors': None})
        response = self.send_request(request)
        return response

    def delete_cors(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri,
                                      uri_params = {'cors': None})
        debug(u"delete_cors(%s)" % uri)
        response = self.send_request(request)
        return response

    def set_lifecycle_policy(self, uri, policy):
        headers = SortedDict(ignore_case = True)
        headers['content-md5'] = generate_content_md5(policy)
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers=headers, body = policy,
                                      uri_params = {'lifecycle': None})
        debug(u"set_lifecycle_policy(%s): policy-xml: %s" % (uri, policy))
        response = self.send_request(request)
        return response

    def set_payer(self, uri):
        headers = SortedDict(ignore_case = True)
        headers['content-type'] = 'application/xml'
        body = '<RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
        if self.config.requester_pays:
            body += '<Payer>Requester</Payer>\n'
        else:
            body += '<Payer>BucketOwner</Payer>\n'
        body += '</RequestPaymentConfiguration>\n'
        request = self.create_request("BUCKET_CREATE", uri = uri, body = body,
                                      uri_params = {'requestPayment': None})
        response = self.send_request(request)
        return response

    def get_lifecycle_policy(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'lifecycle': None})
        debug(u"get_lifecycle_policy(%s)" % uri)
        response = self.send_request(request)

        debug(u"%s: Got Lifecycle Policy" % response['status'])
        return response

    def delete_lifecycle_policy(self, uri):
        request = self.create_request("BUCKET_DELETE", uri = uri,
                                      uri_params = {'lifecycle': None})
        debug(u"delete_lifecycle_policy(%s)" % uri)
        response = self.send_request(request)
        return response

    def set_notification_policy(self, uri, policy):
        headers = SortedDict(ignore_case = True)
        if self.config.skip_destination_validation:
            headers["x-amz-skip-destination-validation"] = "True"
        request = self.create_request("BUCKET_CREATE", uri = uri,
                                      headers = headers, body = policy,
                                      uri_params = {'notification': None})
        debug(u"set_notification_policy(%s): policy-xml: %s" % (uri, policy))
        response = self.send_request(request)
        return response

    def get_notification_policy(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'notification': None})
        debug(u"get_notification_policy(%s)" % uri)
        response = self.send_request(request)

        debug(u"%s: Got notification Policy" % response['status'])
        return response

    def delete_notification_policy(self, uri):
        empty_config = '<NotificationConfiguration></NotificationConfiguration>'
        return self.set_notification_policy(uri, empty_config)

    def set_tagging(self, uri, tagsets):
        if uri.type != "s3":
            raise ValueError("Expected URI type 's3', got '%s'" % uri.type)
        body = '<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        body += '<TagSet>'
        for (key, val) in tagsets:
            body += '<Tag>'
            body += ('    <Key>%s</Key>' % key)
            body += ('    <Value>%s</Value>' % val)
            body += '</Tag>'
        body += '</TagSet>'
        body += '</Tagging>'
        headers = SortedDict(ignore_case=True)
        headers['content-md5'] = generate_content_md5(body)
        if uri.has_object():
            request = self.create_request("OBJECT_PUT", uri=uri,
                                          headers=headers, body=body,
                                          uri_params={'tagging': None})
        else:
            request = self.create_request("BUCKET_CREATE", bucket=uri.bucket(),
                                          headers=headers, body=body,
                                          uri_params={'tagging': None})
        debug(u"set_tagging(%s): tagset-xml: %s" % (uri, body))
        response = self.send_request(request)
        return response

    def get_tagging(self, uri):
        if uri.has_object():
            request = self.create_request("OBJECT_GET", uri=uri,
                                          uri_params={'tagging': None})
        else:
            request = self.create_request("BUCKET_LIST", bucket=uri.bucket(),
                                          uri_params={'tagging': None})
        debug(u"get_tagging(%s)" % uri)
        response = self.send_request(request)
        xml_data = response["data"]
        # extract list of tag sets
        tagsets = getListFromXml(xml_data, "Tag")
        debug(u"%s: Got object tagging" % response['status'])
        return tagsets

    def delete_tagging(self, uri):
        if uri.has_object():
            request = self.create_request("OBJECT_DELETE", uri=uri,
                                          uri_params={'tagging': None})
        else:
            request = self.create_request("BUCKET_DELETE", bucket=uri.bucket(),
                                          uri_params={'tagging': None})
        debug(u"delete_tagging(%s)" % uri)
        response = self.send_request(request)
        return response

    def get_multipart(self, uri, uri_params=None, limit=-1):
        upload_list = []
        for truncated, uploads in self.get_multipart_streaming(uri,
                                                               uri_params,
                                                               limit):
            upload_list.extend(uploads)

        return upload_list

    def get_multipart_streaming(self, uri, uri_params=None, limit=-1):
        uri_params = uri_params and uri_params.copy() or {}
        bucket = uri.bucket()

        truncated = True
        num_objects = 0
        max_keys = limit

        # It is the "uploads: None" in uri_params that will change the
        # behavior of bucket_list to return multiparts instead of keys
        uri_params['uploads'] = None
        while truncated:
            response = self.bucket_list_noparse(bucket, recursive=True,
                                                uri_params=uri_params,
                                                max_keys=max_keys)

            xml_data = response["data"]
            # extract list of info of uploads
            upload_list = getListFromXml(xml_data, "Upload")
            num_objects += len(upload_list)
            if limit > num_objects:
                max_keys = limit - num_objects

            xml_truncated = getTextFromXml(xml_data, ".//IsTruncated")
            if not xml_truncated or xml_truncated.lower() == "false":
                truncated = False

            if truncated:
                if limit == -1 or num_objects < limit:
                    if upload_list:
                        next_key = getTextFromXml(xml_data, "NextKeyMarker")
                        if not next_key:
                            next_key = upload_list[-1]["Key"]
                        uri_params['key-marker'] = next_key

                        upload_id_marker = getTextFromXml(
                            xml_data, "NextUploadIdMarker")
                        if upload_id_marker:
                            uri_params['upload-id-marker'] = upload_id_marker
                        elif 'upload-id-marker' in uri_params:
                            # Clear any pre-existing value
                            del uri_params['upload-id-marker']
                    else:
                        # Unexpectedly, the server lied, and so the previous
                        # response was not truncated. So, no new key to get.
                        yield False, upload_list
                        break
                    debug("Listing continues after '%s'" %
                          uri_params['key-marker'])
                else:
                    yield truncated, upload_list
                    break
            yield truncated, upload_list

    def list_multipart(self, uri, upload_id, uri_params=None, limit=-1):
        part_list = []
        for truncated, parts in self.list_multipart_streaming(uri,
                                                              upload_id,
                                                              uri_params,
                                                              limit):
            part_list.extend(parts)

        return part_list

    def list_multipart_streaming(self, uri, upload_id, uri_params=None,
                                 limit=-1):
        uri_params = uri_params and uri_params.copy() or {}

        truncated = True
        num_objects = 0
        max_parts = limit

        while truncated:
            response = self.list_multipart_noparse(uri, upload_id,
                                                   uri_params, max_parts)

            xml_data = response["data"]
            # extract list of multipart upload parts
            part_list = getListFromXml(xml_data, "Part")
            num_objects += len(part_list)
            if limit > num_objects:
                max_parts = limit - num_objects

            xml_truncated = getTextFromXml(xml_data, ".//IsTruncated")
            if not xml_truncated or xml_truncated.lower() == "false":
                truncated = False

            if truncated:
                if limit == -1 or num_objects < limit:
                    if part_list:
                        next_part_number = getTextFromXml(
                            xml_data, "NextPartNumberMarker")
                        if not next_part_number:
                            next_part_number = part_list[-1]["PartNumber"]
                        uri_params['part-number-marker'] = next_part_number
                    else:
                        # Unexpectedly, the server lied, and so the previous
                        # response was not truncated. So, no new part to get.
                        yield False, part_list
                        break
                    debug("Listing continues after Part '%s'" %
                          uri_params['part-number-marker'])
                else:
                    yield truncated, part_list
                    break
            yield truncated, part_list

    def list_multipart_noparse(self, uri, upload_id, uri_params=None,
                               max_parts=-1):
        if uri_params is None:
            uri_params = {}
        if max_parts != -1:
            uri_params['max-parts'] = str(max_parts)
        uri_params['uploadId'] = upload_id
        request = self.create_request("OBJECT_GET", uri=uri,
                                      uri_params=uri_params)
        response = self.send_request(request)
        return response

    def abort_multipart(self, uri, id):
        request = self.create_request("OBJECT_DELETE", uri = uri,
                                      uri_params = {'uploadId': id})
        response = self.send_request(request)
        return response

    def get_accesslog(self, uri):
        request = self.create_request("BUCKET_LIST", bucket = uri.bucket(),
                                      uri_params = {'logging': None})
        response = self.send_request(request)
        accesslog = AccessLog(response['data'])
        return accesslog

    def set_accesslog_acl(self, uri):
        acl = self.get_acl(uri)
        debug("Current ACL(%s): %s" % (uri.uri(), acl))
        acl.appendGrantee(GranteeLogDelivery("READ_ACP"))
        acl.appendGrantee(GranteeLogDelivery("WRITE"))
        debug("Updated ACL(%s): %s" % (uri.uri(), acl))
        self.set_acl(uri, acl)

    def set_accesslog(self, uri, enable, log_target_prefix_uri = None, acl_public = False):
        accesslog = AccessLog()
        if enable:
            accesslog.enableLogging(log_target_prefix_uri)
            accesslog.setAclPublic(acl_public)
        else:
            accesslog.disableLogging()

        body = "%s" % accesslog
        debug(u"set_accesslog(%s): accesslog-xml: %s" % (uri, body))

        request = self.create_request("BUCKET_CREATE", bucket = uri.bucket(),
                                      body = body, uri_params = {'logging': None})
        try:
            response = self.send_request(request)
        except S3Error as e:
            if e.info['Code'] == "InvalidTargetBucketForLogging":
                info("Setting up log-delivery ACL for target bucket.")
                self.set_accesslog_acl(S3Uri(u"s3://%s" % log_target_prefix_uri.bucket()))
                response = self.send_request(request)
            else:
                raise
        return accesslog, response

    def create_request(self, operation, uri = None, bucket = None, object = None, headers = None, body = "", uri_params = None):
        resource = { 'bucket' : None, 'uri' : "/" }

        if uri and (bucket or object):
            raise ValueError("Both 'uri' and either 'bucket' or 'object' parameters supplied")
        ## If URI is given use that instead of bucket/object parameters
        if uri:
            bucket = uri.bucket()
            object = uri.has_object() and uri.object() or None

        if bucket:
            resource['bucket'] = bucket
            if object:
                resource['uri'] = "/" + object

        method_string = S3.http_methods.getkey(S3.operations[operation] & S3.http_methods["MASK"])

        request = S3Request(self, method_string, resource, headers, body, uri_params)

        debug("CreateRequest: resource[uri]=%s", resource['uri'])
        return request

    def _fail_wait(self, retries):
        # Wait a few seconds. The more it fails the more we wait.
        return (self.config.max_retries - retries + 1) * 3

    def _http_redirection_handler(self, request, response, fn, *args, **kwargs):
        # Region info might already be available through the x-amz-bucket-region header
        redir_region = response['headers'].get('x-amz-bucket-region')

        if 'data' in response and len(response['data']) > 0:
            redir_bucket = getTextFromXml(response['data'], ".//Bucket")
            redir_hostname = getTextFromXml(response['data'], ".//Endpoint")
            self.set_hostname(redir_bucket, redir_hostname)
            info(u'Redirected to: %s', redir_hostname)
            if redir_region:
                S3Request.region_map[redir_bucket] = redir_region
                info(u'Redirected to region: %s', redir_region)
            return fn(*args, **kwargs)
        elif request.method_string == 'HEAD':
            # Head is a special case, redirection info usually are in the body
            # but there is no body for an HEAD request.
            location_url = response['headers'].get('location')
            if location_url:
                # Sometimes a "location" http header could be available and
                # can help us deduce the redirection path.
                # It is the case of "dns-style" syntax, but not for "path-style" syntax.
                if location_url.startswith("http://"):
                    location_url = location_url[7:]
                elif location_url.startswith("https://"):
                    location_url = location_url[8:]
                location_url = urlparse('https://' + location_url).hostname
                redir_bucket = request.resource['bucket']
                self.set_hostname(redir_bucket, location_url)
                info(u'Redirected to: %s', location_url)
                if redir_region:
                    S3Request.region_map[redir_bucket] = redir_region
                    info(u'Redirected to region: %s', redir_region)
                return fn(*args, **kwargs)
            warning(u'Redirection error: No info provided by the server to where should be forwarded the request (HEAD request). (Hint target region: %s)', redir_region)

        raise S3Error(response)

    def _http_400_handler(self, request, response, fn, *args, **kwargs):
        """
        Returns None if no handler available for the specific error code
        """
        # AWS response AuthorizationHeaderMalformed means we sent the request to the wrong region
        # get the right region out of the response and send it there.
        if 'data' in response and len(response['data']) > 0:
            failureCode = getTextFromXml(response['data'], 'Code')
            if failureCode == 'AuthorizationHeaderMalformed':
                # we sent the request to the wrong region
                region = getTextFromXml(response['data'], 'Region')
                if region is not None:
                    S3Request.region_map[request.resource['bucket']] = region
                    info('Forwarding request to %s', region)
                    return fn(*args, **kwargs)
                else:
                    warning(u'Could not determine the bucket location. Please consider using the --region parameter.')

            elif failureCode == 'InvalidRequest':
                message = getTextFromXml(response['data'], 'Message')
                if message == 'The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.':
                    debug(u'Endpoint requires signature v4')
                    self.endpoint_requires_signature_v4 = True
                    return fn(*args, **kwargs)

            elif failureCode == 'InvalidArgument':
                # returned by DreamObjects on send_request and send_file,
                # which doesn't support signature v4. Retry with signature v2
                if not request.use_signature_v2() and not self.fallback_to_signature_v2: # have not tried with v2 yet
                    debug(u'Falling back to signature v2')
                    self.fallback_to_signature_v2 = True
                    return fn(*args, **kwargs)
        else:
            # returned by DreamObjects on recv_file, which doesn't support signature v4. Retry with signature v2
            if not request.use_signature_v2() and not self.fallback_to_signature_v2:
                # have not tried with v2 yet
                debug(u'Falling back to signature v2')
                self.fallback_to_signature_v2 = True
                return fn(*args, **kwargs)

        return None

    def _http_403_handler(self, request, response, fn, *args, **kwargs):
        if 'data' in response and len(response['data']) > 0:
            failureCode = getTextFromXml(response['data'], 'Code')
            if failureCode == 'AccessDenied':
                # traditional HTTP 403
                message = getTextFromXml(response['data'], 'Message')
                if message == 'AWS authentication requires a valid Date or x-amz-date header': # message from an Eucalyptus walrus server
                    if not request.use_signature_v2() and not self.fallback_to_signature_v2: # have not tried with v2 yet
                        debug(u'Falling back to signature v2')
                        self.fallback_to_signature_v2 = True
                        return fn(*args, **kwargs)

        raise S3Error(response)

    def update_region_inner_request(self, request):
        """Get and update region for the request if needed.

        Signature v4 needs the region of the bucket or the request will fail
        with the indication of the correct region.
        We are trying to avoid this failure by preemptively getting the
        correct region to use, if not provided by the user.
        """
        if request.resource.get('bucket') and not request.use_signature_v2() \
           and S3Request.region_map.get(
                request.resource['bucket'], Config().bucket_location
               ) == "US":
            debug("===== SEND Inner request to determine the bucket region "
                  "=====")
            try:
                s3_uri = S3Uri(u's3://' + request.resource['bucket'])
                # "force_us_default" should prevent infinite recursivity because
                # it will set the region_map dict.
                region = self.get_bucket_location(s3_uri, force_us_default=True)
                if region is not None:
                    S3Request.region_map[request.resource['bucket']] = region
                debug("===== SUCCESS Inner request to determine the bucket "
                      "region (%r) =====", region)
            except Exception as exc:
                # Ignore errors, it is just an optimisation, so nothing critical
                debug("getlocation inner request failure reason: %s", exc)
                debug("===== FAILED Inner request to determine the bucket "
                      "region =====")

    def send_request(self, request, retries=None):
        if retries is None:
            retries = self.config.max_retries
        self.update_region_inner_request(request)

        request.body = encode_to_s3(request.body)
        headers = request.headers

        method_string, resource, headers = request.get_triplet()
        response = {}
        debug("Processing request, please wait...")

        conn = None
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            # TODO: Check what was supposed to be the usage of conn.path here
            # Currently this is always "None" all the time as not defined in ConnMan
            uri = self.format_uri(resource, conn.path)
            debug("Sending request method_string=%r, uri=%r, headers=%r, body=(%i bytes)" % (method_string, uri, headers, len(request.body or "")))
            conn.c.request(method_string, uri, request.body, headers)
            http_response = conn.c.getresponse()
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertHeaderTupleListToDict(http_response.getheaders())
            response["data"] =  http_response.read()
            if "x-amz-meta-s3cmd-attrs" in response["headers"]:
                attrs = parse_attrs_header(response["headers"]["x-amz-meta-s3cmd-attrs"])
                response["s3cmd-attrs"] = attrs
            ConnMan.put(conn)
        except (S3SSLError, S3SSLCertificateError):
            # In case of failure to validate the certificate for a ssl
            # connection,no need to retry, abort immediately
            raise
        except (IOError, Exception) as e:
            debug("Response:\n" + pprint.pformat(response))
            if ((hasattr(e, 'errno') and e.errno
                 and e.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ETIMEDOUT))
                or "[Errno 104]" in str(e)
                or "[Errno 32]" in str(e)
               ) and not isinstance(e, SocketTimeoutException):
                raise
            # When the connection is broken, BadStatusLine is raised with py2
            # and RemoteDisconnected is raised by py3 with a trap:
            # RemoteDisconnected has an errno field with a None value.

            # close the connection and re-establish
            ConnMan.close(conn)
            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                return self.send_request(request, retries - 1)
            else:
                raise S3RequestError("Request failed for: %s" % resource['uri'])

        except:
            # Only KeyboardInterrupt and SystemExit will not be covered by Exception
            debug("Response:\n" + pprint.pformat(response))
            raise

        debug("Response:\n" + pprint.pformat(response))

        if response["status"] in [301, 307]:
            ## RedirectTemporary or RedirectPermanent
            return self._http_redirection_handler(request, response, self.send_request, request)

        if response["status"] == 400:
            handler_fn = self._http_400_handler(request, response, self.send_request, request)
            if handler_fn:
                return handler_fn
            err = S3Error(response)
            if retries and err.code in ['BadDigest', 'OperationAborted',
                                        'TokenRefreshRequired', 'RequestTimeout']:
                warning(u"Retrying failed request: %s (%s)" % (resource['uri'], err))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                return self.send_request(request, retries - 1)
            raise err

        if response["status"] == 403:
            return self._http_403_handler(request, response, self.send_request, request)
        if response["status"] == 405: # Method Not Allowed.  Don't retry.
            raise S3Error(response)

        if response["status"] >= 500 or response["status"] == 429:
            e = S3Error(response)

            if response["status"] == 501:
                ## NotImplemented server error - no need to retry
                retries = 0

            if retries:
                warning(u"Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                return self.send_request(request, retries - 1)
            else:
                raise e

        if response["status"] < 200 or response["status"] > 299:
            raise S3Error(response)

        return response

    def send_request_with_progress(self, request, labels, operation_size=0):
        """Wrapper around send_request for slow requests.

        To be able to show progression for small requests
        """
        if not self.config.progress_meter:
            info("Sending slow request, please wait...")
            return self.send_request(request)

        if 'action' not in labels:
            labels[u'action'] = u'request'
        progress = self.config.progress_class(labels, operation_size)

        try:
            response = self.send_request(request)
        except Exception as exc:
            progress.done("failed")
            raise

        progress.update(current_position=operation_size)
        progress.done("done")

        return response

    def send_file(self, request, stream, labels, buffer = '', throttle = 0,
                  retries = None, offset = 0, chunk_size = -1,
                  use_expect_continue = None):
        if retries is None:
            retries = self.config.max_retries
        self.update_region_inner_request(request)

        if use_expect_continue is None:
            use_expect_continue = self.config.use_http_expect
        if self.expect_continue_not_supported and use_expect_continue:
            use_expect_continue = False

        headers = request.headers

        size_left = size_total = int(headers["content-length"])

        filename = stream.stream_name
        if self.config.progress_meter:
            labels[u'action'] = u'upload'
            progress = self.config.progress_class(labels, size_total)
        else:
            info("Sending file '%s', please wait..." % filename)
        timestamp_start = time.time()

        if buffer:
            sha256_hash = checksum_sha256_buffer(buffer, offset, size_total)
        else:
            sha256_hash = checksum_sha256_file(stream, offset, size_total)
        request.body = sha256_hash

        if use_expect_continue:
            if not size_total:
                use_expect_continue = False
            else:
                headers['expect'] = '100-continue'

        method_string, resource, headers = request.get_triplet()
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            conn.c.putrequest(method_string, self.format_uri(resource, conn.path))
            for header in headers.keys():
                conn.c.putheader(encode_to_s3(header), encode_to_s3(headers[header]))
            conn.c.endheaders()
        except ParameterError as e:
            raise
        except Exception as e:
            if self.config.progress_meter:
                progress.done("failed")
            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                # Connection error -> same throttle value
                return self.send_file(request, stream, labels, buffer, throttle, retries - 1, offset, chunk_size)
            else:
                raise S3UploadError("Upload failed for: %s" % resource['uri'])
        if buffer == '':
            stream.seek(offset)
        md5_hash = md5()

        try:
            http_response = None
            if use_expect_continue:
                # Wait for the 100-Continue before sending the content
                readable, writable, exceptional = select.select([conn.c.sock],[], [], EXPECT_CONTINUE_TIMEOUT)
                if readable:
                    # 100-CONTINUE STATUS RECEIVED, get it before continuing.
                    http_response = conn.c.getresponse()
                elif not writable and not exceptional:
                    warning("HTTP Expect Continue feature disabled because of no reply of the server in %.2fs.", EXPECT_CONTINUE_TIMEOUT)
                    self.expect_continue_not_supported = True
                    use_expect_continue = False

            if not use_expect_continue or (http_response and http_response.status == ConnMan.CONTINUE):
                if http_response:
                    # CONTINUE case. Reset the response
                    http_response.read()
                    conn.c._HTTPConnection__state = ConnMan._CS_REQ_SENT

                while size_left > 0:
                    #debug("SendFile: Reading up to %d bytes from '%s' - remaining bytes: %s" % (self.config.send_chunk, filename, size_left))
                    l = min(self.config.send_chunk, size_left)
                    if buffer == '':
                        data = stream.read(l)
                    else:
                        data = buffer

                    if not data:
                        raise InvalidFileError("File smaller than expected. Was the file truncated?")

                    if self.config.limitrate > 0:
                        start_time = time.time()

                    md5_hash.update(data)

                    conn.c.wrapper_send_body(data)
                    if self.config.progress_meter:
                        progress.update(delta_position = len(data))
                    size_left -= len(data)

                    #throttle
                    limitrate_throttle = throttle
                    if self.config.limitrate > 0:
                        real_duration = time.time() - start_time
                        expected_duration = float(l) / self.config.limitrate
                        limitrate_throttle = max(expected_duration - real_duration, limitrate_throttle)
                    if limitrate_throttle:
                        time.sleep(min(limitrate_throttle, self.config.throttle_max))

                md5_computed = md5_hash.hexdigest()
                http_response = conn.c.getresponse()

            response = {}
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertHeaderTupleListToDict(http_response.getheaders())
            response["data"] = http_response.read()
            response["size"] = size_total
            ConnMan.put(conn)
            debug(u"Response:\n" + pprint.pformat(response))
        except ParameterError as e:
            raise
        except InvalidFileError as e:
            if self.config.progress_meter:
                progress.done("failed")
            raise
        except Exception as e:
            if self.config.progress_meter:
                progress.done("failed")
            if retries:
                known_error = False
                if ((hasattr(e, 'errno') and e.errno
                     and e.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ETIMEDOUT))
                    or "[Errno 104]" in str(e) or "[Errno 32]" in str(e)
                   ) and not isinstance(e, SocketTimeoutException):
                    # We have to detect these errors by looking at the error string
                    # Connection reset by peer and Broken pipe
                    # The server broke the connection early with an error like
                    # in a HTTP Expect Continue case even if asked nothing.
                    try:
                        http_response = conn.c.getresponse()
                        response = {}
                        response["status"] = http_response.status
                        response["reason"] = http_response.reason
                        response["headers"] = convertHeaderTupleListToDict(http_response.getheaders())
                        response["data"] = http_response.read()
                        response["size"] = size_total
                        known_error = True
                    except Exception:
                        error("Cannot retrieve any response status before encountering an EPIPE or ECONNRESET exception")
                if not known_error:
                    warning("Upload failed: %s (%s)" % (resource['uri'], e))
                    warning("Waiting %d sec..." % self._fail_wait(retries))
                    time.sleep(self._fail_wait(retries))
                    # Connection error -> same throttle value
                    return self.send_file(request, stream, labels, buffer, throttle,
                                      retries - 1, offset, chunk_size, use_expect_continue)
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

        if response["status"] in [301, 307]:
            ## RedirectTemporary or RedirectPermanent
            return self._http_redirection_handler(request, response,
                                                  self.send_file, request, stream, labels, buffer, offset = offset, chunk_size = chunk_size, use_expect_continue = use_expect_continue)

        if response["status"] == 400:
            handler_fn = self._http_400_handler(request, response,
                                                self.send_file, request, stream, labels, buffer, offset = offset, chunk_size = chunk_size, use_expect_continue = use_expect_continue)
            if handler_fn:
                return handler_fn
            err = S3Error(response)
            if err.code not in ['BadDigest', 'OperationAborted',
                                'TokenRefreshRequired', 'RequestTimeout']:
                raise err
            # else the error will be handled later with a retry

        if response["status"] == 403:
            return self._http_403_handler(request, response,
                                          self.send_file, request, stream, labels, buffer, offset = offset, chunk_size = chunk_size, use_expect_continue = use_expect_continue)

        if response["status"] == 417 and retries:
            # Expect 100-continue not supported by proxy/server
            self.expect_continue_not_supported = True
            return self.send_file(request, stream, labels, buffer, throttle,
                                  retries - 1, offset, chunk_size, use_expect_continue = False)

        # S3 from time to time doesn't send ETag back in a response :-(
        # Force re-upload here.
        if 'etag' not in response['headers']:
            response['headers']['etag'] = ''

        if response["status"] < 200 or response["status"] > 299:
            try_retry = False
            if response["status"] >= 500:
                # AWS internal error - retry
                try_retry = True
                if response["status"] == 503:
                    ## SlowDown error
                    throttle = throttle and throttle * 5 or 0.01
                elif response["status"] == 507:
                    # Not an AWS error, but s3 compatible server possible error:
                    # InsufficientStorage
                    try_retry = False
            elif response["status"] == 429:
                # Not an AWS error, but s3 compatible server possible error:
                # TooManyRequests/Busy/slowdown
                try_retry = True
                throttle = throttle and throttle * 5 or 0.01
            elif response["status"] >= 400:
                err = S3Error(response)
                ## Retriable client error?
                if err.code in ['BadDigest', 'OperationAborted', 'TokenRefreshRequired', 'RequestTimeout']:
                    try_retry = True

            err = S3Error(response)
            if try_retry:
                if retries:
                    warning("Upload failed: %s (%s)" % (resource['uri'], err))
                    if throttle:
                        warning("Retrying on lower speed (throttle=%0.2f)" % throttle)
                    warning("Waiting %d sec..." % self._fail_wait(retries))
                    time.sleep(self._fail_wait(retries))
                    return self.send_file(request, stream, labels, buffer, throttle,
                                          retries - 1, offset, chunk_size, use_expect_continue)
                else:
                    warning("Too many failures. Giving up on '%s'" % filename)
                    raise S3UploadError("%s" % err)

            ## Non-recoverable error
            raise err

        debug("MD5 sums: computed=%s, received=%s" % (md5_computed, response["headers"].get('etag', '').strip('"\'')))
        ## when using KMS encryption, MD5 etag value will not match
        md5_from_s3 = response["headers"].get("etag", "").strip('"\'')
        if ('-' not in md5_from_s3) and (md5_from_s3 != md5_hash.hexdigest()) and response["headers"].get("x-amz-server-side-encryption") != 'aws:kms':
            warning("MD5 Sums don't match!")
            if retries:
                warning("Retrying upload of %s" % (filename))
                return self.send_file(request, stream, labels, buffer, throttle,
                                      retries - 1, offset, chunk_size, use_expect_continue)
            else:
                warning("Too many failures. Giving up on '%s'" % filename)
                raise S3UploadError("MD5 sums of sent and received files don't match!")

        return response

    def send_file_multipart(self, stream, headers, uri, size, extra_label=""):
        timestamp_start = time.time()
        upload = MultiPartUpload(self, stream, uri, headers, size)
        upload.upload_all_parts(extra_label)
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

    def copy_file_multipart(self, src_uri, dst_uri, size, headers,
                            extra_label=""):
        return self.send_file_multipart(src_uri, headers, dst_uri, size,
                                        extra_label)

    def recv_file(self, request, stream, labels, start_position=0, retries=None):
        if retries is None:
            retries = self.config.max_retries
        self.update_region_inner_request(request)

        method_string, resource, headers = request.get_triplet()
        filename = stream.stream_name
        if self.config.progress_meter:
            labels[u'action'] = u'download'
            progress = self.config.progress_class(labels, 0)
        else:
            info("Receiving file '%s', please wait..." % filename)
        timestamp_start = time.time()

        conn = None
        try:
            conn = ConnMan.get(self.get_hostname(resource['bucket']))
            conn.c.putrequest(method_string, self.format_uri(resource, conn.path))
            for header in headers.keys():
                conn.c.putheader(encode_to_s3(header), encode_to_s3(headers[header]))
            if start_position > 0:
                debug("Requesting Range: %d .. end" % start_position)
                conn.c.putheader("Range", "bytes=%d-" % start_position)
            conn.c.endheaders()
            response = {}
            http_response = conn.c.getresponse()
            response["status"] = http_response.status
            response["reason"] = http_response.reason
            response["headers"] = convertHeaderTupleListToDict(http_response.getheaders())
            if "x-amz-meta-s3cmd-attrs" in response["headers"]:
                attrs = parse_attrs_header(response["headers"]["x-amz-meta-s3cmd-attrs"])
                response["s3cmd-attrs"] = attrs
            debug("Response:\n" + pprint.pformat(response))
        except ParameterError as e:
            raise
        except (IOError, Exception) as e:
            if self.config.progress_meter:
                progress.done("failed")
            if ((hasattr(e, 'errno') and e.errno and
                 e.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ETIMEDOUT))
                or "[Errno 104]" in str(e) or "[Errno 32]" in str(e)
               ) and not isinstance(e, SocketTimeoutException):
                raise

            # close the connection and re-establish
            ConnMan.close(conn)

            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                # Connection error -> same throttle value
                return self.recv_file(request, stream, labels, start_position,
                                      retries=retries - 1)
            else:
                raise S3DownloadError("Download failed for: %s" % resource['uri'])

        if response["status"] < 200 or response["status"] > 299:
            # In case of error, we still need to flush the read buffer to be able to reuse
            # the connection
            response['data'] = http_response.read()

        if response["status"] in [301, 307]:
            ## RedirectPermanent or RedirectTemporary
            return self._http_redirection_handler(request, response,
                                                  self.recv_file, request,
                                                  stream, labels, start_position)

        if response["status"] == 400:
            handler_fn = self._http_400_handler(request, response, self.recv_file,
                                                request, stream, labels, start_position)
            if handler_fn:
                return handler_fn
            raise S3Error(response)

        if response["status"] == 403:
            return self._http_403_handler(request, response, self.recv_file,
                                          request, stream, labels, start_position)

        if response["status"] < 200 or response["status"] > 299:
            try_retry = False
            if response["status"] == 429:
                # Not an AWS error, but s3 compatible server possible error:
                # TooManyRequests/Busy/slowdown
                try_retry = True

            elif response["status"] == 503:
                # SlowDown error
                try_retry = True

            if try_retry:
                resource_uri = resource['uri']
                if retries:
                    retry_delay = self._fail_wait(retries)
                    warning("Retrying failed request: %s (%s)"
                            % (resource_uri, S3Error(response)))
                    warning("Waiting %d sec..." % retry_delay)
                    time.sleep(retry_delay)
                    return self.recv_file(request, stream, labels, start_position,
                                          retries=retries - 1)
                else:
                    warning("Too many failures. Giving up on '%s'" % resource_uri)
                    raise S3DownloadError("Download failed for: %s" % resource_uri)

            # Non-recoverable error
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
                    expected_duration = float(this_chunk) / self.config.limitrate
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
        except (IOError, Exception) as e:
            if self.config.progress_meter:
                progress.done("failed")
            if ((hasattr(e, 'errno') and e.errno
                 and e.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ETIMEDOUT))
                or "[Errno 104]" in str(e) or "[Errno 32]" in str(e)
               ) and not isinstance(e, SocketTimeoutException):
                raise
            # close the connection and re-establish
            ConnMan.close(conn)

            if retries:
                warning("Retrying failed request: %s (%s)" % (resource['uri'], e))
                warning("Waiting %d sec..." % self._fail_wait(retries))
                time.sleep(self._fail_wait(retries))
                # Connection error -> same throttle value
                return self.recv_file(request, stream, labels, current_position,
                                      retries=retries - 1)
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

        md5_from_s3 = response["headers"].get("etag", "").strip('"\'')
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
                except IOError as e:
                    if e.errno != errno.ENOENT:
                        warning("Unable to open file: %s: %s" % (filename, e))
                    warning("Unable to verify MD5. Assume it matches.")

        response["md5match"] = response.get("md5") == md5_from_s3
        response["elapsed"] = timestamp_end - timestamp_start
        response["size"] = current_position
        response["speed"] = response["elapsed"] and float(response["size"]) / response["elapsed"] or float(-1)
        if response["size"] != start_position + int(response["headers"]["content-length"]):
            warning("Reported size (%s) does not match received size (%s)" % (
                start_position + int(response["headers"]["content-length"]), response["size"]))
        debug("ReceiveFile: Computed MD5 = %s" % response.get("md5"))
        # avoid ETags from multipart uploads that aren't the real md5
        if ('-' not in md5_from_s3 and not response["md5match"]) and (response["headers"].get("x-amz-server-side-encryption") != 'aws:kms'):
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

# vim:et:ts=4:sts=4:ai
