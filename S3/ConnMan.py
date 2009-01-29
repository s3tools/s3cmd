import httplib
from urlparse import urlparse
from threading import Semaphore
from logging import debug, info, warning, error

from Config import Config

__all__ = [ "ConnMan" ]

class http_connection(object):
	def __init__(self, id, hostname, ssl):
		self.hostname = hostname
		self.ssl = ssl
		self.id = id
		self.counter = 0
		if not ssl:
			self.c = httplib.HTTPConnection(hostname)
		else:
			self.c = httplib.HTTPSConnection(hostname)

class ConnMan(object):
	conn_pool_sem = Semaphore()
	conn_pool = {}
	conn_max_counter = 800	## AWS closes connection after some ~90 requests

	@staticmethod
	def get(hostname, ssl = None):
		if ssl == None:
			ssl = Config().use_https
		conn = None
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
			conn = http_connection(conn_id, hostname, ssl)
			conn.c.connect()
		conn.counter += 1
		return conn

	@staticmethod
	def put(conn):
		if conn.counter >= ConnMan.conn_max_counter:
			conn.c.close()
			debug("ConnMan.put(): closing over-used connection")
			return

		ConnMan.conn_pool_sem.acquire()
		ConnMan.conn_pool[conn.id].append(conn)
		ConnMan.conn_pool_sem.release()
		debug("ConnMan.put(): connection put back to pool (%s#%d)" % (conn.id, conn.counter))

