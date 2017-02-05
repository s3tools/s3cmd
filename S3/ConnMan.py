# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import absolute_import

import sys
if sys.version_info >= (3,0):
    from .Custom_httplib3x import httplib
else:
    from .Custom_httplib27 import httplib
import ssl
from threading import Semaphore
from logging import debug
try:
    # python 3 support
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from .Config import Config
from .Exceptions import ParameterError
from .Utils import getBucketFromHostname

if not 'CertificateError ' in ssl.__dict__:
    class CertificateError(Exception):
        pass
    ssl.CertificateError = CertificateError

__all__ = [ "ConnMan" ]


class http_connection(object):
    context = None
    context_set = False

    @staticmethod
    def _ssl_verified_context(cafile):
        cfg = Config()
        context = None
        try:
            context = ssl.create_default_context(cafile=cafile)
        except AttributeError: # no ssl.create_default_context
            pass
        if context and not cfg.check_ssl_hostname:
            context.check_hostname = False
            debug(u'Disabling SSL certificate hostname checking')

        return context

    @staticmethod
    def _ssl_unverified_context(cafile):
        debug(u'Disabling SSL certificate checking')
        context = None
        try:
            context = ssl._create_unverified_context(cafile=cafile,
                                                     cert_reqs=ssl.CERT_NONE)
        except AttributeError: # no ssl._create_unverified_context
            pass
        return context

    @staticmethod
    def _ssl_context():
        if http_connection.context_set:
            return http_connection.context

        cfg = Config()
        cafile = cfg.ca_certs_file
        if cafile == "":
            cafile = None
        debug(u"Using ca_certs_file %s", cafile)

        if cfg.check_ssl_certificate:
            context = http_connection._ssl_verified_context(cafile)
        else:
            context = http_connection._ssl_unverified_context(cafile)

        http_connection.context = context
        http_connection.context_set = True
        return context

    def forgive_wildcard_cert(self, cert, hostname):
        """
        Wildcard matching for *.s3.amazonaws.com and similar per region.

        Per http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html:
        "We recommend that all bucket names comply with DNS naming conventions."

        Per http://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html:
        "When using virtual hosted-style buckets with SSL, the SSL
        wild card certificate only matches buckets that do not contain
        periods. To work around this, use HTTP or write your own
        certificate verification logic."

        Therefore, we need a custom validation routine that allows
        mybucket.example.com.s3.amazonaws.com to be considered a valid
        hostname for the *.s3.amazonaws.com wildcard cert, and for the
        region-specific *.s3-[region].amazonaws.com wildcard cert.

        We also forgive non-S3 wildcard certificates should the
        hostname match, to allow compatibility with other S3
        API-compatible storage providers.
        """
        debug(u'checking SSL subjectAltName as forgiving wildcard cert')
        san = cert.get('subjectAltName', ())
        cleaned_host_bucket_config = urlparse('https://' + Config.host_bucket).hostname
        for key, value in san:
            if key == 'DNS':
                if value.startswith('*.s3') and \
                   (value.endswith('.amazonaws.com') and hostname.endswith('.amazonaws.com')) or \
                   (value.endswith('.amazonaws.com.cn') and hostname.endswith('.amazonaws.com.cn')):
                    return True
                elif value == cleaned_host_bucket_config % \
                               {'bucket': '*', 'location': Config.bucket_location} and \
                     hostname.endswith(cleaned_host_bucket_config % \
                                       {'bucket': '', 'location': Config.bucket_location}):
                    return True
        return False

    def match_hostname(self):
        cert = self.c.sock.getpeercert()
        try:
            ssl.match_hostname(cert, self.hostname)
        except AttributeError: # old ssl module doesn't have this function
            return
        except ValueError: # empty SSL cert means underlying SSL library didn't validate it, we don't either.
            return
        except ssl.CertificateError as e:
            if not self.forgive_wildcard_cert(cert, self.hostname):
                raise e

    @staticmethod
    def _https_connection(hostname, port=None):
        try:
            context = http_connection._ssl_context()
            # Wilcard certificates do not work with DNS-style named buckets.
            bucket_name, success = getBucketFromHostname(hostname)
            if success and '.' in bucket_name:
                # this merely delays running the hostname check until
                # after the connection is made and we get control
                # back.  We then run the same check, relaxed for S3's
                # wildcard certificates.
                debug(u'Bucket name contains "." character, disabling initial SSL hostname check')
                check_hostname = False
                if context:
                    context.check_hostname = False
            else:
                if context:
                    check_hostname = context.check_hostname
                else:
                    # Earliest version of python that don't have context,
                    # don't check hostnames anyway
                    check_hostname = True
            # Note, we are probably needed to try to set check_hostname because of that bug:
            # http://bugs.python.org/issue22959
            conn = httplib.HTTPSConnection(hostname, port, context=context, check_hostname=check_hostname)
            debug(u'httplib.HTTPSConnection() has both context and check_hostname')
        except TypeError:
            try:
                # in case check_hostname parameter is not present try again
                conn = httplib.HTTPSConnection(hostname, port, context=context)
                debug(u'httplib.HTTPSConnection() has only context')
            except TypeError:
                # in case even context parameter is not present try one last time
                conn = httplib.HTTPSConnection(hostname, port)
                debug(u'httplib.HTTPSConnection() has neither context nor check_hostname')
        return conn

    def __init__(self, id, hostname, ssl, cfg):
        self.ssl = ssl
        self.id = id
        self.counter = 0
        # Whatever is the input, ensure to have clean hostname and port
        parsed_hostname = urlparse('https://' + hostname)
        self.hostname = parsed_hostname.hostname
        self.port = parsed_hostname.port
        if parsed_hostname.path and parsed_hostname.path != '/':
            self.path = parsed_hostname.path.rstrip('/')
            debug(u'endpoint path set to %s', self.path)
        else:
            self.path = None

        """
        History note:
        In a perfect world, or in the future:
        - All http proxies would support CONNECT/tunnel, and so there would be no need
        for using "absolute URIs" in format_uri.
        - All s3-like servers would work well whether using relative or ABSOLUTE URIs.
        But currently, what is currently common:
        - Proxies without support for CONNECT for http, and so "absolute URIs" have to
        be used.
        - Proxies with support for CONNECT for httpS but s3-like servers having issues
        with "absolute URIs", so relative one still have to be used as the requests will
        pass as-is, through the proxy because of the CONNECT mode.
        """

        if not cfg.proxy_host:
            if ssl:
                self.c = http_connection._https_connection(hostname)
                debug(u'non-proxied HTTPSConnection(%s, %s)', self.hostname, self.port)
            else:
                self.c = httplib.HTTPConnection(self.hostname, self.port)
                debug(u'non-proxied HTTPConnection(%s, %s)', self.hostname, self.port)
        else:
            if ssl:
                self.c = http_connection._https_connection(cfg.proxy_host, cfg.proxy_port)
                debug(u'proxied HTTPSConnection(%s, %s)', cfg.proxy_host, cfg.proxy_port)
                self.c.set_tunnel(self.hostname, self.port)
                debug(u'tunnel to %s, %s', self.hostname, self.port)
            else:
                self.c = httplib.HTTPConnection(cfg.proxy_host, cfg.proxy_port)
                debug(u'proxied HTTPConnection(%s, %s)', cfg.proxy_host, cfg.proxy_port)
                # No tunnel here for the moment


class ConnMan(object):
    _CS_REQ_SENT = httplib._CS_REQ_SENT
    CONTINUE = httplib.CONTINUE
    conn_pool_sem = Semaphore()
    conn_pool = {}
    conn_max_counter = 800    ## AWS closes connection after some ~90 requests

    @staticmethod
    def get(hostname, ssl = None):
        cfg = Config()
        if ssl == None:
            ssl = cfg.use_https
        conn = None
        if cfg.proxy_host != "":
            if ssl and sys.hexversion < 0x02070000:
                raise ParameterError("use_https=True can't be used with proxy on Python <2.7")
            conn_id = "proxy://%s:%s" % (cfg.proxy_host, cfg.proxy_port)
        else:
            conn_id = "http%s://%s" % (ssl and "s" or "", hostname)
        ConnMan.conn_pool_sem.acquire()
        if conn_id not in ConnMan.conn_pool:
            ConnMan.conn_pool[conn_id] = []
        if len(ConnMan.conn_pool[conn_id]):
            conn = ConnMan.conn_pool[conn_id].pop()
            debug("ConnMan.get(): re-using connection: %s#%d" % (conn.id, conn.counter))
        ConnMan.conn_pool_sem.release()
        if not conn:
            debug("ConnMan.get(): creating new connection: %s" % conn_id)
            conn = http_connection(conn_id, hostname, ssl, cfg)
            conn.c.connect()
            if conn.ssl and cfg.check_ssl_certificate and cfg.check_ssl_hostname:
                conn.match_hostname()
        conn.counter += 1
        return conn

    @staticmethod
    def put(conn):
        if conn.id.startswith("proxy://"):
            conn.c.close()
            debug("ConnMan.put(): closing proxy connection (keep-alive not yet supported)")
            return

        if conn.counter >= ConnMan.conn_max_counter:
            conn.c.close()
            debug("ConnMan.put(): closing over-used connection")
            return

        ConnMan.conn_pool_sem.acquire()
        ConnMan.conn_pool[conn.id].append(conn)
        ConnMan.conn_pool_sem.release()
        debug("ConnMan.put(): connection put back to pool (%s#%d)" % (conn.id, conn.counter))
