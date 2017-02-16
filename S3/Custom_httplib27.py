from __future__ import absolute_import, print_function

import os
import httplib

from httplib import (_CS_REQ_SENT, _CS_REQ_STARTED, CONTINUE, UnknownProtocol,
                     CannotSendHeader, NO_CONTENT, NOT_MODIFIED, EXPECTATION_FAILED,
                     HTTPMessage, HTTPException)

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from .Utils import encode_to_s3


_METHODS_EXPECTING_BODY = ['PATCH', 'POST', 'PUT']

# Fixed python 2.X httplib to be able to support
# Expect: 100-Continue http feature
# Inspired by:
# http://bugs.python.org/file26357/issue1346874-273.patch

def httpresponse_patched_begin(self):
    """ Re-implemented httplib begin function
    to not loop over "100 CONTINUE" status replies
    but to report it to higher level so it can be processed.
    """
    if self.msg is not None:
        # we've already started reading the response
        return

    # read only one status even if we get a non-100 response
    version, status, reason = self._read_status()

    self.status = status
    self.reason = reason.strip()
    if version == 'HTTP/1.0':
        self.version = 10
    elif version.startswith('HTTP/1.'):
        self.version = 11   # use HTTP/1.1 code for HTTP/1.x where x>=1
    elif version == 'HTTP/0.9':
        self.version = 9
    else:
        raise UnknownProtocol(version)

    if self.version == 9:
        self.length = None
        self.chunked = 0
        self.will_close = 1
        self.msg = HTTPMessage(StringIO())
        return

    self.msg = HTTPMessage(self.fp, 0)
    if self.debuglevel > 0:
        for hdr in self.msg.headers:
            print("header:", hdr, end=" ")

    # don't let the msg keep an fp
    self.msg.fp = None

    # are we using the chunked-style of transfer encoding?
    tr_enc = self.msg.getheader('transfer-encoding')
    if tr_enc and tr_enc.lower() == "chunked":
        self.chunked = 1
        self.chunk_left = None
    else:
        self.chunked = 0

    # will the connection close at the end of the response?
    self.will_close = self._check_close()

    # do we have a Content-Length?
    # NOTE: RFC 2616, S4.4, #3 says we ignore this if tr_enc is "chunked"
    length = self.msg.getheader('content-length')
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
    if not self.will_close and \
        not self.chunked and \
        self.length is None:
        self.will_close = 1


def httpconnection_patched_set_content_length(self, body, method):
    ## REIMPLEMENTED because new in last httplib but needed by send_request
    # Set the content-length based on the body. If the body is "empty", we
    # set Content-Length: 0 for methods that expect a body (RFC 7230,
    # Section 3.3.2). If the body is set for other methods, we set the
    # header provided we can figure out what the length is.
    thelen = None
    if body is None and method.upper() in _METHODS_EXPECTING_BODY:
        thelen = '0'
    elif body is not None:
        try:
            thelen = str(len(body))
        except (TypeError, AttributeError):
            # If this is a file-like object, try to
            # fstat its file descriptor
            try:
                thelen = str(os.fstat(body.fileno()).st_size)
            except (AttributeError, OSError):
                # Don't send a length if this failed
                if self.debuglevel > 0: print("Cannot stat!!")

    if thelen is not None:
        self.putheader('Content-Length', thelen)

def httpconnection_patched_send_request(self, method, url, body, headers):
    # Honor explicitly requested Host: and Accept-Encoding: headers.
    header_names = dict.fromkeys([k.lower() for k in headers])
    skips = {}
    if 'host' in header_names:
        skips['skip_host'] = 1
    if 'accept-encoding' in header_names:
        skips['skip_accept_encoding'] = 1

    expect_continue = False
    for hdr, value in headers.iteritems():
        if 'expect' == hdr.lower() and '100-continue' in value.lower():
            expect_continue = True

    self.putrequest(method, url, **skips)

    if 'content-length' not in header_names:
        self._set_content_length(body, method)
    for hdr, value in headers.iteritems():
        self.putheader(hdr, value)

    # If an Expect: 100-continue was sent, we need to check for a 417
    # Expectation Failed to avoid unecessarily sending the body
    # See RFC 2616 8.2.3
    if not expect_continue:
        self.endheaders(body)
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
            self.send(body)

def httpconnection_patched_endheaders(self, message_body=None):
    """Indicate that the last header line has been sent to the server.

    This method sends the request to the server.  The optional
    message_body argument can be used to pass a message body
    associated with the request.  The message body will be sent in
    the same packet as the message headers if it is string, otherwise it is
    sent as a separate packet.
    """
    if self._HTTPConnection__state == _CS_REQ_STARTED:
        self._HTTPConnection__state = _CS_REQ_SENT
    else:
        raise CannotSendHeader()
    self._send_output(message_body)

# TCP Maximum Segment Size (MSS) is determined by the TCP stack on
# a per-connection basis.  There is no simple and efficient
# platform independent mechanism for determining the MSS, so
# instead a reasonable estimate is chosen.  The getsockopt()
# interface using the TCP_MAXSEG parameter may be a suitable
# approach on some operating systems. A value of 16KiB is chosen
# as a reasonable estimate of the maximum MSS.
mss = 16384

def httpconnection_patched_send_output(self, message_body=None):
    """Send the currently buffered request and clear the buffer.

    Appends an extra \\r\\n to the buffer.
    A message_body may be specified, to be appended to the request.
    """
    self._buffer.extend((b"", b""))
    msg = b"\r\n".join(self._buffer)
    del self._buffer[:]

    msg = encode_to_s3(msg)
    # If msg and message_body are sent in a single send() call,
    # it will avoid performance problems caused by the interaction
    # between delayed ack and the Nagle algorithm.
    if isinstance(message_body, str) and len(message_body) < mss:
        msg += message_body
        message_body = None
    self.send(msg)
    if message_body is not None:
        #message_body was not a string (i.e. it is a file) and
        #we must run the risk of Nagle
        self.send(message_body)


class ExpectationFailed(HTTPException):
    pass

# Wrappers #

def httpconnection_patched_wrapper_send_body(self, message_body):
    self.send(message_body)


httplib.HTTPResponse.begin = httpresponse_patched_begin
httplib.HTTPConnection.endheaders = httpconnection_patched_endheaders
httplib.HTTPConnection._send_output = httpconnection_patched_send_output
httplib.HTTPConnection._set_content_length = httpconnection_patched_set_content_length
httplib.HTTPConnection._send_request = httpconnection_patched_send_request

# Interfaces added to httplib.HTTPConnection:
httplib.HTTPConnection.wrapper_send_body = httpconnection_patched_wrapper_send_body
