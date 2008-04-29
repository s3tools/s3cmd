## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

from BidirMap import BidirMap

class SortedDictIterator(object):
	def __init__(self, sorted_dict, keys):
		self.sorted_dict = sorted_dict
		self.keys = keys

	def next(self):
		try:
			return self.keys.pop(0)
		except IndexError:
			raise StopIteration

class SortedDict(dict):
	keys_sort_lowercase = True

	def keys(self):
		keys = dict.keys(self)
		if self.keys_sort_lowercase:
			# Translation map
			xlat_map = BidirMap()
			for key in keys:
				xlat_map[key.lower()] = key
			# Lowercase keys
			lc_keys = xlat_map.keys()
			lc_keys.sort()
			return [xlat_map[k] for k in lc_keys]
		else:
			keys.sort()
			return keys

	def __iter__(self):
		return SortedDictIterator(self, self.keys())

if __name__ == "__main__":
	d = SortedDict()
	d['AWS'] = 1
	d['Action'] = 2
	d['america'] = 3
	d.keys_sort_lowercase = True
	print "Wanted: Action, america, AWS,"
	print "Got:   ",
	for key in d:
		print "%s," % key,
	print "   __iter__()"
	d.keys_return_lowercase = True
	print "Got:   ",
	for key in d.keys():
		print "%s," % key,
	print "   keys()"
