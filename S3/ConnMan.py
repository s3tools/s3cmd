## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

import sys
import httplib
import ssl
from urlparse import urlparse
from threading import Semaphore
from logging import debug, info, warning, error

from Config import Config
from Exceptions import ParameterError

__all__ = [ "ConnMan" ]

class http_connection(object):
    context = None
    context_set = False

    @staticmethod
    def _ssl_verified_context(cafile):
        context = None
        try:
            context = ssl.create_default_context(cafile=cafile)
        except AttributeError: # no ssl.create_default_context
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

        context = http_connection._ssl_verified_context(cafile)

        if context and not cfg.check_ssl_certificate:
            context.check_hostname = False
            debug(u'Disabling hostname checking')

        http_connection.context = context
        http_connection.context_set = True
        return context

    @staticmethod
    def _https_connection(hostname, port=None):
        try:
            context = http_connection._ssl_context()
            conn = httplib.HTTPSConnection(hostname, port, context=context)
        except TypeError:
            conn = httplib.HTTPSConnection(hostname, port)
        return conn

    def __init__(self, id, hostname, ssl, cfg):
        self.hostname = hostname
        self.ssl = ssl
        self.id = id
        self.counter = 0

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

            # S3's wildcart certificate doesn't work with DNS-style named buckets.
            if 'amazonaws.com' in hostname and http_connection.context:
                http_connection.context.check_hostname = False
                debug(u'Disabling SSL certificate hostname verification for S3 wildcard cert')

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

