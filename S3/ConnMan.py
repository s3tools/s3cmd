# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

import re
import sys
import httplib
import ssl
from threading import Semaphore
from logging import debug

from Config import Config
from Exceptions import ParameterError
from Utils import getBucketFromHostname

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
        debug(u"Using ca_certs_file %s" % cafile)

        if cfg.check_ssl_certificate:
            context = http_connection._ssl_verified_context(cafile)
        else:
            context = http_connection._ssl_unverified_context(cafile)

        http_connection.context = context
        http_connection.context_set = True
        return context

    def forgive_wildcard_cert(self, cert, e):
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
        for key, value in san:
            if key == 'DNS':
                if value.startswith('*.s3') and \
                   (value.endswith('.amazonaws.com') and self.hostname.endswith('.amazonaws.com')) or \
                   (value.endswith('.amazonaws.com.cn') and self.hostname.endswith('.amazonaws.com.cn')):
                    return
                elif value == (Config.host_bucket % {'bucket': '*'}) and \
                     self.hostname.endswith('.' + '.'.join(Config.host_bucket.split('.')[1:])):
                    return
        raise e

    def match_hostname(self):
        cert = self.c.sock.getpeercert()
        try:
            if re.match('[^\:]+:[0-9]+', self.hostname):
                ssl.match_hostname(cert, self.hostname.split(':')[0])
            else:
                ssl.match_hostname(cert, self.hostname)
        except AttributeError: # old ssl module doesn't have this function
            return
        except ValueError: # empty SSL cert means underlying SSL library didn't validate it, we don't either.
            return
        except ssl.CertificateError, e:
            self.forgive_wildcard_cert(cert, e)

    @staticmethod
    def _https_connection(hostname, port=None):
        check_hostname = True
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
        self.hostname = hostname

        if not ssl:
            if cfg.proxy_host != "":
                self.c = httplib.HTTPConnection(cfg.proxy_host, cfg.proxy_port)
                debug(u'proxied HTTPConnection(%s, %s)' % (cfg.proxy_host, cfg.proxy_port))
            else:
                self.c = httplib.HTTPConnection(hostname)
                debug(u'non-proxied HTTPConnection(%s)' % hostname)
        else:
            if cfg.proxy_host != "":
                self.c = http_connection._https_connection(cfg.proxy_host, cfg.proxy_port)
                self.c.set_tunnel(hostname)
                debug(u'proxied HTTPSConnection(%s, %s)' % (cfg.proxy_host, cfg.proxy_port))
                debug(u'tunnel to %s' % hostname)
            else:
                self.c = http_connection._https_connection(hostname)
                debug(u'non-proxied HTTPSConnection(%s)' % hostname)


class ConnMan(object):
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
        if not ConnMan.conn_pool.has_key(conn_id):
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

