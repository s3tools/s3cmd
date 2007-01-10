import logging
from logging import debug, info, warn, error
import re

class ConfigParser:
	def __init__(self, file, sections = []):
		self.cfg = {}
		self.parse_file(file, sections)
	
	def parse_file(self, file, sections = []):
		if type(sections) != type([]):
			sections = [sections]
		in_our_section = True
		f = open(file, "r")
		r_comment = re.compile("^\s*#.*")
		r_empty = re.compile("^\s*$")
		r_section = re.compile("^\[([^\]]+)\]")
		r_data = re.compile("^\s*(?P<key>\w+)\s*=\s*(?P<value>.*)")
		r_quotes = re.compile("^\"(.*)\"\s*$")
		for line in f:
			if r_comment.match(line) or r_empty.match(line):
				continue
			is_section = r_section.match(line)
			if is_section:
				section = is_section.groups()[0]
				in_our_section = (section in sections) or (len(sections) == 0)
				continue
			is_data = r_data.match(line)
			if is_data and in_our_section:
				data = is_data.groupdict()
				if r_quotes.match(data["value"]):
					data["value"] = data["value"][1:-1]
				debug("ConfigParser: %s->%s" % (data["key"], data["value"]))
				self.__setitem__(data["key"], data["value"])
				continue

	def __getitem__(self, name):
		return self.cfg[name]
	
	def __setitem__(self, name, value):
		self.cfg[name] = value
	
	def get(self, name, default = None):
		if self.cfg.has_key(name):
			return self.cfg[name]
		return default

if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
	parser = ConfigParser("/home/mludvig/.s3cfg")
	print parser["access_key"]
