## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

class SortedDictIterator(object):
	def __init__(self, dict):
		self.dict = dict
		self.keys = dict.keys()
		self.index = 0
		self.length = len(self.keys)

	def next(self):
		if self.length <= self.index:
			raise StopIteration

		retval = self.keys[self.index]
		self.index += 1
		return retval


class SortedDict(dict):
	def __setitem__(self, name, value):
		try:
			value = value.strip()
		except:
			pass
		dict.__setitem__(self, name.lower(), value)

	def __iter__(self):
		return SortedDictIterator(self)
	

	def keys(self):
		keys = dict.keys(self)
		keys.sort()
		return keys
	
	def popitem(self):
		keys = self.keys()
		if len(keys) < 1:
			raise KeyError("popitem(): dictionary is empty")
		retval = (keys[0], dict.__getitem__(self, keys[0]))
		dict.__delitem__(self, keys[0])
		return retval


