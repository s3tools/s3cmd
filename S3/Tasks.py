## s3cmd library - Threading support
## http://s3tools.org
##
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import httplib
from urlparse import urlparse
from logging import debug, info, warning, error
import Queue

from ConnMan import ConnMan
from Worker import Worker
from Exceptions import S3Error, PermanentError, RequeueTaskException
from S3Uri import S3Uri

class Task(object):
	def run(self):
		raise NotImplementedError("Please implement run() method in your subclass")

class TaskSetACL(Task):
	def __init__(self, s3, uri_str, acl_public):
		self.s3 = s3
		self.uri_str = uri_str
		self.uri = S3Uri(uri_str)
		self.acl_public = acl_public

	def run(self):
		acl = self.s3.get_acl(self.uri)
		debug(u"acl: %s - %r" % (self.uri, acl.grantees))
		if self.acl_public:
			if acl.isAnonRead():
				return False
			acl.grantAnonRead()
		else:
			if not acl.isAnonRead():
				return False
			acl.revokeAnonRead()
		response = self.s3.set_acl(self.uri, acl)
		if response['status'] == 200:
			return True
		elif response['status'] >= 500:
			raise RequeueTaskError()
		else:
			raise S3Error(response)

class FetchUrlTask(Task):
	def __init__(self, url):
		self.url = url

	def run(self):
		o = urlparse(self.url)
		conn = ConnMan.get(o.netloc)
		conn.c.request("GET", self.url)
		r = conn.c.getresponse()
		if r.length > 0:
			r.data = r.read()
		ConnMan.put(conn)
		return r

	def __str__(self):
		return "%s" % self.url
	
	def __repr__(self):
		return "FetchUrlTask('%s')" % self.url

if __name__ == "__main__":
	urls_in = [
		"http://tmp.logix.cz",
		"http://non-existent.logix.cz",
		"http://www.logix.cz/blah.html",
		"http://www.logix.cz/michal",
		"http://www.logix.cz/michal/devel/smtp/smtp-client.pl",
		"http://www.logix.cz/michal/devel/smtp/smtp-client.pl.xp",
	]
	urls_err = []

	pool_size = 2
	w = Worker(pool_size)

	## Put all the wanted URLs in the q_in Queue
	for url in urls_in:
		w.q_in.put(FetchUrlTask(url))

	## Read from q_out Queue until all the wanted URLs are fetched
	while len(urls_in):
		try:
			response = w.q_out.get(timeout = 5)
		except Queue.Empty:
			break
		if response.has_key('response'):
			r = response['response']
			print "Main: response: %s: %s (%s)" % (response['task'].url, r.status, r.reason)
			urls_in.remove(response['task'].url)
			if r.status in range(300, 400) and r.getheader("location"):
				location = r.getheader("location")
				print "Main: redirect: %s -> %s" % (response['task'].url, location)
				w.q_in.put(FetchUrlTask(location))
				urls_in.append(location)
		else:
			e = response['exception']
			print "Main: exception: %s: %r %s" % (response['task'].url, e, type(e))
			if isinstance(e, PermanentError):
				print "PermanentError: %s" % response['task'].url
				urls_in.remove(response['task'].url)
				urls_err.append(response['task'].url)
			else:
				w.q_in.put(response['task'])

	w.ev_quit.set()
	for t in w.thread_pool:
		print "Waiting for %s" % t.name
		t.join()
	print "Main: left in urls_in: %s" % urls_in
	print "Main: left in urls_err: %s" % urls_err
	print "All done. Quitting now..."
