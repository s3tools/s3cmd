# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import absolute_import

import sys
import hmac
import base64

from . import Config
from logging import debug
from .Utils import encode_to_s3, time_to_epoch, deunicodise, decode_from_s3
from .SortedDict import SortedDict

import datetime
try:
    # python 3 support
    from urllib import quote
except ImportError:
    from urllib.parse import quote

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
    """
    secret_key = Config.Config().secret_key
    encoded_secret = encode_to_s3(secret_key)
    encoded_str = encode_to_s3(string_to_sign)
    signature = base64.encodestring(hmac.new(encoded_secret, encoded_str, sha1).digest()).strip()
    decoded_signature = decode_from_s3(signature)
    return decoded_signature
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
                               'requestPayment', 'torrent', 'uploadId',
                               'uploads', 'versionId', 'versioning',
                               'versions', 'website',
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
    url = "%(proto)s://%(bucket)s.%(host_base)s/%(object)s?AWSAccessKeyId=%(access_key)s&Expires=%(expiry)d&Signature=%(sig)s" % parms
    if content_disposition:
        url += "&response-content-disposition=" + s3_quote(content_disposition, unicode_output=True)
    if content_type:
        url += "&response-content-type=" + s3_quote(content_type, unicode_output=True)
    return url

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

def s3_quote(param, quote_backslashes=True, unicode_output=False):
    """
    URI encode every byte. UriEncode() must enforce the following rules:
    - URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
    - The space character is a reserved character and must be encoded as "%20" (and not as "+").
    - Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
    - Letters in the hexadecimal value must be uppercase, for example "%1A".
    - Encode the forward slash character, '/', everywhere except in the object key name.
    For example, if the object key name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.
    """
    if quote_backslashes:
        safe_chars = "~"
    else:
        safe_chars = "~/"
    param = encode_to_s3(param)
    param = quote(param, safe=safe_chars)
    if unicode_output:
        param = decode_from_s3(param)
    else:
        param = encode_to_s3(param)
    return param
__all__.append("s3_quote")

def checksum_sha256_file(filename, offset=0, size=None):
    try:
        hash = sha256()
    except:
        # fallback to Crypto SHA256 module
        hash = sha256.new()
    with open(deunicodise(filename),'rb') as f:
        if size is None:
            for chunk in iter(lambda: f.read(8192), b''):
                hash.update(chunk)
        else:
            f.seek(offset)
            size_left = size
            while size_left > 0:
                chunk = f.read(min(8192, size_left))
                size_left -= len(chunk)
                hash.update(chunk)

    return hash

def checksum_sha256_buffer(buffer, offset=0, size=None):
    try:
        hash = sha256()
    except:
        # fallback to Crypto SHA256 module
        hash = sha256.new()
    if size is None:
        hash.update(buffer)
    else:
        hash.update(buffer[offset:offset+size])
    return hash
