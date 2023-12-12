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

from __future__ import absolute_import

import sys
import hmac
try:
    from base64 import encodebytes as encodestring
except ImportError:
    # Python 2 support
    from base64 import encodestring

from . import Config
from logging import debug
from .BaseUtils import encode_to_s3, decode_from_s3, s3_quote, md5, unicode
from .Utils import time_to_epoch, deunicodise, check_bucket_name_dns_support
from .SortedDict import SortedDict

import datetime


from hashlib import sha1, sha256

__all__ = []


def format_param_str(params, always_have_equal=False, limited_keys=None):
    """
    Format URL parameters from a params dict and returns
    ?parm1=val1&parm2=val2 or an empty string if there
    are no parameters.  Output of this function should
    be appended directly to self.resource['uri']
    - Set "always_have_equal" to always have the "=" char for a param even when
    there is no value for it.
    - Set "limited_keys" list to restrict the param string to keys that are
    defined in it.
    """
    if not params:
        return ""

    param_str = ""
    equal_str = always_have_equal and u'=' or ''
    for key in sorted(params.keys()):
        if limited_keys and key not in limited_keys:
            continue
        value = params[key]
        if value in (None, ""):
            param_str += "&%s%s" % (s3_quote(key, unicode_output=True), equal_str)
        else:
            param_str += "&%s=%s" % (key, s3_quote(params[key], unicode_output=True))
    return param_str and "?" + param_str[1:]
__all__.append("format_param_str")


### AWS Version 2 signing
def sign_string_v2(string_to_sign):
    """Sign a string with the secret key, returning base64 encoded results.
    By default the configured secret key is used, but may be overridden as
    an argument.

    Useful for REST authentication. See http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html
    string_to_sign should be utf-8 "bytes".
    and returned signature will be utf-8 encoded "bytes".
    """
    secret_key = Config.Config().secret_key
    signature = encodestring(hmac.new(encode_to_s3(secret_key), string_to_sign, sha1).digest()).strip()
    return signature
__all__.append("sign_string_v2")


def sign_request_v2(method='GET', canonical_uri='/', params=None, cur_headers=None):
    """Sign a string with the secret key, returning base64 encoded results.
    By default the configured secret key is used, but may be overridden as
    an argument.

    Useful for REST authentication. See http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html
    string_to_sign should be utf-8 "bytes".
    """
    # valid sub-resources to be included in sign v2:
    SUBRESOURCES_TO_INCLUDE = ['acl', 'lifecycle', 'location', 'logging',
                               'notification', 'partNumber', 'policy',
                               'requestPayment', 'tagging', 'torrent',
                               'uploadId', 'uploads', 'versionId',
                               'versioning', 'versions', 'website',
                               # Missing of aws s3 doc but needed
                               'delete', 'cors', 'restore']

    if cur_headers is None:
        cur_headers = SortedDict(ignore_case = True)

    access_key = Config.Config().access_key

    string_to_sign  = method + "\n"
    string_to_sign += cur_headers.get("content-md5", "") + "\n"
    string_to_sign += cur_headers.get("content-type", "") + "\n"
    string_to_sign += cur_headers.get("date", "") + "\n"

    for header in sorted(cur_headers.keys()):
        if header.startswith("x-amz-"):
            string_to_sign += header + ":" + cur_headers[header] + "\n"
        if header.startswith("x-emc-"):
            string_to_sign += header + ":"+ cur_headers[header] + "\n"


    canonical_uri = s3_quote(canonical_uri, quote_backslashes=False, unicode_output=True)
    canonical_querystring = format_param_str(params, limited_keys=SUBRESOURCES_TO_INCLUDE)
    # canonical_querystring would be empty if no param given, otherwise it will
    # starts with a "?"
    canonical_uri += canonical_querystring

    string_to_sign += canonical_uri

    debug("SignHeaders: " + repr(string_to_sign))
    signature = decode_from_s3(sign_string_v2(encode_to_s3(string_to_sign)))

    new_headers = SortedDict(list(cur_headers.items()), ignore_case=True)
    new_headers["Authorization"] = "AWS " + access_key + ":" + signature

    return new_headers
__all__.append("sign_request_v2")


def sign_url_v2(url_to_sign, expiry):
    """Sign a URL in s3://bucket/object form with the given expiry
    time. The object will be accessible via the signed URL until the
    AWS key and secret are revoked or the expiry time is reached, even
    if the object is otherwise private.

    See: http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html
    """
    return sign_url_base_v2(
        bucket = url_to_sign.bucket(),
        object = url_to_sign.object(),
        expiry = expiry
    )
__all__.append("sign_url_v2")


def sign_url_base_v2(**parms):
    """Shared implementation of sign_url methods. Takes a hash of 'bucket', 'object' and 'expiry' as args."""
    content_disposition=Config.Config().content_disposition
    content_type=Config.Config().content_type
    parms['expiry']=time_to_epoch(parms['expiry'])
    parms['access_key']=Config.Config().access_key
    parms['host_base']=Config.Config().host_base
    parms['object'] = s3_quote(parms['object'], quote_backslashes=False, unicode_output=True)
    parms['proto'] = 'http'
    if Config.Config().signurl_use_https:
        parms['proto'] = 'https'
    debug("Expiry interpreted as epoch time %s", parms['expiry'])
    signtext = 'GET\n\n\n%(expiry)d\n/%(bucket)s/%(object)s' % parms
    param_separator = '?'
    if content_disposition:
        signtext += param_separator + 'response-content-disposition=' + content_disposition
        param_separator = '&'
    if content_type:
        signtext += param_separator + 'response-content-type=' + content_type
        param_separator = '&'
    debug("Signing plaintext: %r", signtext)
    parms['sig'] = s3_quote(sign_string_v2(encode_to_s3(signtext)), unicode_output=True)
    debug("Urlencoded signature: %s", parms['sig'])
    if check_bucket_name_dns_support(Config.Config().host_bucket, parms['bucket']):
        url = "%(proto)s://%(bucket)s.%(host_base)s/%(object)s"
    else:
        url = "%(proto)s://%(host_base)s/%(bucket)s/%(object)s"
    url += "?AWSAccessKeyId=%(access_key)s&Expires=%(expiry)d&Signature=%(sig)s"
    url = url % parms
    if content_disposition:
        url += "&response-content-disposition=" + s3_quote(content_disposition, unicode_output=True)
    if content_type:
        url += "&response-content-type=" + s3_quote(content_type, unicode_output=True)
    return url
__all__.append("sign_url_base_v2")


def sign(key, msg):
    return hmac.new(key, encode_to_s3(msg), sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    """
    Input: unicode params
    Output: bytes
    """
    kDate = sign(encode_to_s3('AWS4' + key), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def sign_request_v4(method='GET', host='', canonical_uri='/', params=None,
                    region='us-east-1', cur_headers=None, body=b''):
    service = 's3'
    if cur_headers is None:
        cur_headers = SortedDict(ignore_case = True)

    cfg = Config.Config()
    access_key = cfg.access_key
    secret_key = cfg.secret_key

    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')

    signing_key = getSignatureKey(secret_key, datestamp, region, service)


    canonical_uri = s3_quote(canonical_uri, quote_backslashes=False, unicode_output=True)
    canonical_querystring = format_param_str(params, always_have_equal=True).lstrip('?')


    if type(body) == type(sha256(b'')):
        payload_hash = decode_from_s3(body.hexdigest())
    else:
        payload_hash = decode_from_s3(sha256(encode_to_s3(body)).hexdigest())

    canonical_headers = {'host' : host,
                         'x-amz-content-sha256': payload_hash,
                         'x-amz-date' : amzdate
                         }
    signed_headers = 'host;x-amz-content-sha256;x-amz-date'

    for header in cur_headers.keys():
        # avoid duplicate headers and previous Authorization
        if header == 'Authorization' or header in signed_headers.split(';'):
            continue
        canonical_headers[header.strip()] = cur_headers[header].strip()
        signed_headers += ';' + header.strip()

    # sort headers into a string
    canonical_headers_str = ''
    for k, v in sorted(canonical_headers.items()):
        canonical_headers_str += k + ":" + v + "\n"

    canonical_headers = canonical_headers_str
    debug(u"canonical_headers = %s" % canonical_headers)
    signed_headers = ';'.join(sorted(signed_headers.split(';')))

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    debug('Canonical Request:\n%s\n----------------------' % canonical_request)

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' + decode_from_s3(sha256(encode_to_s3(canonical_request)).hexdigest())

    signature = decode_from_s3(hmac.new(signing_key, encode_to_s3(string_to_sign), sha256).hexdigest())
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ',' +  'SignedHeaders=' + signed_headers + ',' + 'Signature=' + signature
    new_headers = SortedDict(cur_headers.items())
    new_headers.update({'x-amz-date':amzdate,
                       'Authorization':authorization_header,
                       'x-amz-content-sha256': payload_hash})
    debug("signature-v4 headers: %s" % new_headers)
    return new_headers
__all__.append("sign_request_v4")


def checksum_file_descriptor(file_desc, offset=0, size=None, hash_func=sha256):
    hash = hash_func()

    if size is None:
        for chunk in iter(lambda: file_desc.read(8192), b''):
            hash.update(chunk)
    else:
        file_desc.seek(offset)
        size_left = size
        while size_left > 0:
            chunk = file_desc.read(min(8192, size_left))
            if not chunk:
                break
            size_left -= len(chunk)
            hash.update(chunk)

    return hash
__all__.append("checksum_file_stream")


def checksum_sha256_file(file, offset=0, size=None):
    if not isinstance(file, unicode):
        # file is directly a file descriptor
        return checksum_file_descriptor(file, offset, size, sha256)

    # Otherwise, we expect file to be a filename
    with open(deunicodise(file),'rb') as fp:
        return checksum_file_descriptor(fp, offset, size, sha256)

__all__.append("checksum_sha256_file")


def checksum_sha256_buffer(buffer, offset=0, size=None):
    hash = sha256()
    if size is None:
        hash.update(buffer)
    else:
        hash.update(buffer[offset:offset+size])
    return hash
__all__.append("checksum_sha256_buffer")


def generate_content_md5(body):
    m = md5(encode_to_s3(body))
    base64md5 = encodestring(m.digest())
    base64md5 = decode_from_s3(base64md5)
    if base64md5[-1] == '\n':
        base64md5 = base64md5[0:-1]
    return decode_from_s3(base64md5)
__all__.append("generate_content_md5")


def hash_file_md5(filename):
    h = md5()
    with open(deunicodise(filename), "rb") as fp:
        while True:
            # Hash 32kB chunks
            data = fp.read(32*1024)
            if not data:
                break
            h.update(data)
    return h.hexdigest()
__all__.append("hash_file_md5")


def calculateChecksum(buffer, mfile, offset, chunk_size, send_chunk):
    md5_hash = md5()
    size_left = chunk_size
    if buffer == '':
        mfile.seek(offset)
        while size_left > 0:
            data = mfile.read(min(send_chunk, size_left))
            if not data:
                break
            md5_hash.update(data)
            size_left -= len(data)
    else:
        md5_hash.update(buffer)

    return md5_hash.hexdigest()
__all__.append("calculateChecksum")
