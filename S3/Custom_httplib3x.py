from __future__ import absolute_import, print_function

import os
import http.client as httplib

from http.client import (_CS_REQ_SENT, _CS_REQ_STARTED, CONTINUE, UnknownProtocol,
                     CannotSendHeader, NO_CONTENT, NOT_MODIFIED, EXPECTATION_FAILED,
                     HTTPMessage, HTTPException)


from io import StringIO


_METHODS_EXPECTING_BODY = ['PATCH', 'POST', 'PUT']

# Fixed python 2.X httplib to be able to support
# Expect: 100-Continue http feature
# Inspired by:
# http://bugs.python.org/file26357/issue1346874-273.patch

def _encode(data, name='data'):
    """Call data.encode("latin-1") but show a better error message."""
    try:
        return data.encode("latin-1")
    except UnicodeEncodeError as err:
        raise UnicodeEncodeError(
            err.encoding,
            err.object,
            err.start,
            err.end,
            "%s (%.20r) is not valid Latin-1. Use %s.encode('utf-8') "
            "if you want to send it encoded in UTF-8." %
            (name.title(), data[err.start:err.end], name)) from None

def httpresponse_patched_begin(self):
    """ Re-implemented httplib begin function
    to not loop over "100 CONTINUE" status replies
    but to report it to higher level so it can be processed.
    """

    if self.headers is not None:
        # we've already started reading the response
        return

    # read only one status even if we get a non-100 response
    version, status, reason = self._read_status()

    self.code = self.status = status
    self.reason = reason.strip()
    if version in ('HTTP/1.0', 'HTTP/0.9'):
        # Some servers might still return "0.9", treat it as 1.0 anyway
        self.version = 10
    elif version.startswith('HTTP/1.'):
        self.version = 11   # use HTTP/1.1 code for HTTP/1.x where x>=1
    else:
        raise UnknownProtocol(version)

    self.headers = self.msg = httplib.parse_headers(self.fp)

    if self.debuglevel > 0:
        for hdr in self.headers:
            print("header:", hdr, end=" ")

    # are we using the chunked-style of transfer encoding?
    tr_enc = self.headers.get('transfer-encoding')
    if tr_enc and tr_enc.lower() == "chunked":
        self.chunked = True
        self.chunk_left = None
    else:
        self.chunked = False

    # will the connection close at the end of the response?
    self.will_close = self._check_close()

    # do we have a Content-Length?
    # NOTE: RFC 2616, S4.4, #3 says we ignore this if tr_enc is "chunked"
    self.length = None
    length = self.headers.get('content-length')
    if length and not self.chunked:
        try:
            self.length = int(length)
        except ValueError:
            self.length = None
        else:
            if self.length < 0:  # ignore nonsensical negative lengths
                self.length = None
    else:
        self.length = None

    # does the body have a fixed length? (of zero)
    if (status == NO_CONTENT or status == NOT_MODIFIED or
        100 <= status < 200 or      # 1xx codes
        self._method == 'HEAD'):
        self.length = 0

    # if the connection remains open, and we aren't using chunked, and
    # a content-length was not provided, then assume that the connection
    # WILL close.
    if (not self.will_close and
        not self.chunked and
        self.length is None):
        self.will_close = True

# No need to override httplib with this one, as it is only used by send_request
def httpconnection_patched_get_content_length(body, method):
    """## REIMPLEMENTED because new in last httplib but needed by send_request"""
    """Get the content-length based on the body.

    If the body is None, we set Content-Length: 0 for methods that expect
    a body (RFC 7230, Section 3.3.2). We also set the Content-Length for
    any method if the body is a str or bytes-like object and not a file.
    """
    if body is None:
        # do an explicit check for not None here to distinguish
        # between unset and set but empty
        if method.upper() in _METHODS_EXPECTING_BODY:
            return 0
        else:
            return None

    if hasattr(body, 'read'):
        # file-like object.
        return None

    try:
        # does it implement the buffer protocol (bytes, bytearray, array)?
        mv = memoryview(body)
        return mv.nbytes
    except TypeError:
        pass

    if isinstance(body, str):
        return len(body)

    return None

def httpconnection_patched_send_request(self, method, url, body, headers,
                                        encode_chunked=False):
    # Honor explicitly requested Host: and Accept-Encoding: headers.
    header_names = dict.fromkeys([k.lower() for k in headers])
    skips = {}
    if 'host' in header_names:
        skips['skip_host'] = 1
    if 'accept-encoding' in header_names:
        skips['skip_accept_encoding'] = 1

    expect_continue = False
    for hdr, value in headers.items():
        if 'expect' == hdr.lower() and '100-continue' in value.lower():
            expect_continue = True

    self.putrequest(method, url, **skips)

    # chunked encoding will happen if HTTP/1.1 is used and either
    # the caller passes encode_chunked=True or the following
    # conditions hold:
    # 1. content-length has not been explicitly set
    # 2. the body is a file or iterable, but not a str or bytes-like
    # 3. Transfer-Encoding has NOT been explicitly set by the caller

    if 'content-length' not in header_names:
        # only chunk body if not explicitly set for backwards
        # compatibility, assuming the client code is already handling the
        # chunking
        if 'transfer-encoding' not in header_names:
            # if content-length cannot be automatically determined, fall
            # back to chunked encoding
            encode_chunked = False
            content_length = httpconnection_patched_get_content_length(body, method)
            if content_length is None:
                if body is not None:
                    if self.debuglevel > 0:
                        print('Unable to determine size of %r' % body)
                    encode_chunked = True
                    self.putheader('Transfer-Encoding', 'chunked')
            else:
                self.putheader('Content-Length', str(content_length))
    else:
        encode_chunked = False

    for hdr, value in headers.items():
        self.putheader(hdr, value)

    if isinstance(body, str):
        # RFC 2616 Section 3.7.1 says that text default has a
        # default charset of iso-8859-1.
        body = _encode(body, 'body')

    # If an Expect: 100-continue was sent, we need to check for a 417
    # Expectation Failed to avoid unecessarily sending the body
    # See RFC 2616 8.2.3
    if not expect_continue:
        self.endheaders(body, encode_chunked=encode_chunked)
    else:
        if not body:
            raise HTTPException("A body is required when expecting "
                                "100-continue")
        self.endheaders()
        resp = self.getresponse()
        resp.read()
        self._HTTPConnection__state = _CS_REQ_SENT
        if resp.status == EXPECTATION_FAILED:
            raise ExpectationFailed()
        elif resp.status == CONTINUE:
            self.wrapper_send_body(body, encode_chunked)

def httpconnection_patched_endheaders(self, message_body=None, *, encode_chunked=False):
    """REIMPLEMENTED because new argument encode_chunked added after py 3.4"""
    """Indicate that the last header line has been sent to the server.

    This method sends the request to the server.  The optional message_body
    argument can be used to pass a message body associated with the
    request.
    """
    if self._HTTPConnection__state == _CS_REQ_STARTED:
        self._HTTPConnection__state = _CS_REQ_SENT
    else:
        raise CannotSendHeader()
    self._send_output(message_body, encode_chunked=encode_chunked)

def httpconnection_patched_read_readable(self, readable):
    """REIMPLEMENTED because needed by send_output and added after py 3.4
    """
    blocksize = 8192
    if self.debuglevel > 0:
        print("sendIng a read()able")
    encode = self._is_textIO(readable)
    if encode and self.debuglevel > 0:
        print("encoding file using iso-8859-1")
    while True:
        datablock = readable.read(blocksize)
        if not datablock:
            break
        if encode:
            datablock = datablock.encode("iso-8859-1")
        yield datablock

def httpconnection_patched_send_output(self, message_body=None,
                                       encode_chunked=False):
    """REIMPLEMENTED because needed by endheaders and parameter
    encode_chunked was added"""
    """Send the currently buffered request and clear the buffer.

    Appends an extra \\r\\n to the buffer.
    A message_body may be specified, to be appended to the request.
    """
    self._buffer.extend((b"", b""))
    msg = b"\r\n".join(self._buffer)
    del self._buffer[:]
    self.send(msg)

    if message_body is not None:
        self.wrapper_send_body(message_body, encode_chunked)


class ExpectationFailed(HTTPException):
    pass

# Wrappers #

def httpconnection_patched_wrapper_send_body(self, message_body, encode_chunked=False):
    # create a consistent interface to message_body
    if hasattr(message_body, 'read'):
        # Let file-like take precedence over byte-like.  This
        # is needed to allow the current position of mmap'ed
        # files to be taken into account.
        chunks = self._read_readable(message_body)
    else:
        try:
            # this is solely to check to see if message_body
            # implements the buffer API.  it /would/ be easier
            # to capture if PyObject_CheckBuffer was exposed
            # to Python.
            memoryview(message_body)
        except TypeError:
            try:
                chunks = iter(message_body)
            except TypeError:
                raise TypeError("message_body should be a bytes-like "
                                "object or an iterable, got %r"
                                % type(message_body))
        else:
            # the object implements the buffer interface and
            # can be passed directly into socket methods
            chunks = (message_body,)

    for chunk in chunks:
        if not chunk:
            if self.debuglevel > 0:
                print('Zero length chunk ignored')
            continue

        if encode_chunked and self._http_vsn == 11:
            # chunked encoding
            chunk = '{:X}\r\n'.format(len(chunk)).encode('ascii') + chunk \
                + b'\r\n'
        self.send(chunk)

    if encode_chunked and self._http_vsn == 11:
        # end chunked transfer
        self.send(b'0\r\n\r\n')



httplib.HTTPResponse.begin = httpresponse_patched_begin
httplib.HTTPConnection.endheaders = httpconnection_patched_endheaders
httplib.HTTPConnection._send_readable = httpconnection_patched_read_readable
httplib.HTTPConnection._send_output = httpconnection_patched_send_output
httplib.HTTPConnection._send_request = httpconnection_patched_send_request

# Interfaces added to httplib.HTTPConnection:
httplib.HTTPConnection.wrapper_send_body = httpconnection_patched_wrapper_send_body
