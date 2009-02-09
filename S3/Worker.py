## s3cmd library - Threading support
## http://s3tools.org
##
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

## See the code in S3/Tasks.py for an example use

from threading import Thread, Semaphore, Event
from Queue import Queue, Empty
from Exceptions import PermanentError, RequeueTaskException

__all__ = [ 'Worker' ]

class Worker(object):
	def __init__(self, nr_threads):
		self.thread_pool = []
		self.q_in = Queue()
		self.q_out = Queue()
		self.ev_quit = Event()
		for i in range(nr_threads):
			t_name = "Worker-%d" % i
			t = Thread(target = self.worker, 
			           kwargs = { 't_name' : t_name })
			t.name = t_name
			t.start()
			self.thread_pool.append(t)

	def worker(self, t_name):
		while not self.ev_quit.is_set():
			try:
				task = self.q_in.get(timeout = 0.2)
			except Empty:
				continue
			try:
				response = task.run()
				#print "%s response: %r" % (t_name, response)
				self.q_out.put({ 
					'task' : task,
					'response' : response
				})
			except RequeueTaskException:
				print "%s requeuing: %s" % (t_name, str(task))
				self.q_in.put(task)
			except Exception, e:
				print "%s exception: %r" % (t_name, e)
				self.q_out.put({ 
					'task' : task,
					'exception' : e
				})
		return

