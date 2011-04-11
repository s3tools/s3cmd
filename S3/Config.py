## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import logging
from logging import debug, info, warning, error
import re
import Progress
from SortedDict import SortedDict

class Config(object):
	_instance = None
	_parsed_files = []
	_doc = {}
	access_key = ""
	secret_key = ""
	host_base = "s3.amazonaws.com"
	host_bucket = "%(bucket)s.s3.amazonaws.com"
	simpledb_host = "sdb.amazonaws.com"
	cloudfront_host = "cloudfront.amazonaws.com"
	cloudfront_resource = "/2010-07-15/distribution"
	verbosity = logging.WARNING
	progress_meter = True
	progress_class = Progress.ProgressCR
	send_chunk = 4096
	recv_chunk = 4096
	list_md5 = False
	human_readable_sizes = False
	extra_headers = SortedDict(ignore_case = True)
	force = False
	enable = None
	get_continue = False
	skip_existing = False
	recursive = False
	acl_public = None
	acl_grants = []
	acl_revokes = []
	proxy_host = ""
	proxy_port = 3128
	encrypt = False
	dry_run = False
	preserve_attrs = True
	preserve_attrs_list = [ 
		'uname',	# Verbose owner Name (e.g. 'root')
		'uid',		# Numeric user ID (e.g. 0)
		'gname',	# Group name (e.g. 'users')
		'gid',		# Numeric group ID (e.g. 100)
		'atime',	# Last access timestamp
		'mtime',	# Modification timestamp
		'ctime',	# Creation timestamp
		'mode',		# File mode (e.g. rwxr-xr-x = 755)
		#'acl',		# Full ACL (not yet supported)
	]
	delete_removed = False
	_doc['delete_removed'] = "[sync] Remove remote S3 objects when local file has been deleted"
	gpg_passphrase = ""
	gpg_command = ""
	gpg_encrypt = "%(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
	gpg_decrypt = "%(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
	use_https = False
	bucket_location = "US"
	default_mime_type = "binary/octet-stream"
	guess_mime_type = True
	# List of checks to be performed for 'sync'
	sync_checks = ['size', 'md5']	# 'weak-timestamp'
	# List of compiled REGEXPs
	exclude = []
	include = []
	# Dict mapping compiled REGEXPs back to their textual form
	debug_exclude = {}
	debug_include = {}
	encoding = "utf-8"
	urlencoding_mode = "normal"
	log_target_prefix = ""
	reduced_redundancy = False
	follow_symlinks = False
	socket_timeout = 300

	## Creating a singleton
	def __new__(self, configfile = None):
		if self._instance is None:
			self._instance = object.__new__(self)
		return self._instance

	def __init__(self, configfile = None):
		if configfile:
			self.read_config_file(configfile)

	def option_list(self):
		retval = []
		for option in dir(self):
			## Skip attributes that start with underscore or are not string, int or bool
			option_type = type(getattr(Config, option))
			if option.startswith("_") or \
			   not (option_type in (
			   		type("string"),	# str
			        	type(42),	# int
					type(True))):	# bool
				continue
			retval.append(option)
		return retval

	def read_config_file(self, configfile):
		cp = ConfigParser(configfile)
		for option in self.option_list():
			self.update_option(option, cp.get(option))
		self._parsed_files.append(configfile)

	def dump_config(self, stream):
		ConfigDumper(stream).dump("default", self)

	def update_option(self, option, value):
		if value is None:
			return
		#### Special treatment of some options
		## verbosity must be known to "logging" module
		if option == "verbosity":
			try:
				setattr(Config, "verbosity", logging._levelNames[value])
			except KeyError:
				error("Config: verbosity level '%s' is not valid" % value)
		## allow yes/no, true/false, on/off and 1/0 for boolean options
		elif type(getattr(Config, option)) is type(True):	# bool
			if str(value).lower() in ("true", "yes", "on", "1"):
				setattr(Config, option, True)
			elif str(value).lower() in ("false", "no", "off", "0"):
				setattr(Config, option, False)
			else:
				error("Config: value of option '%s' must be Yes or No, not '%s'" % (option, value))
		elif type(getattr(Config, option)) is type(42):		# int
			try:
				setattr(Config, option, int(value))
			except ValueError, e:
				error("Config: value of option '%s' must be an integer, not '%s'" % (option, value))
		else:							# string
			setattr(Config, option, value)

class ConfigParser(object):
	def __init__(self, file, sections = []):
		self.cfg = {}
		self.parse_file(file, sections)
	
	def parse_file(self, file, sections = []):
		debug("ConfigParser: Reading file '%s'" % file)
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
				self.__setitem__(data["key"], data["value"])
				if data["key"] in ("access_key", "secret_key", "gpg_passphrase"):
					print_value = (data["value"][:2]+"...%d_chars..."+data["value"][-1:]) % (len(data["value"]) - 3)
				else:
					print_value = data["value"]
				debug("ConfigParser: %s->%s" % (data["key"], print_value))
				continue
			warning("Ignoring invalid line in '%s': %s" % (file, line))

	def __getitem__(self, name):
		return self.cfg[name]
	
	def __setitem__(self, name, value):
		self.cfg[name] = value
	
	def get(self, name, default = None):
		if self.cfg.has_key(name):
			return self.cfg[name]
		return default

class ConfigDumper(object):
	def __init__(self, stream):
		self.stream = stream

	def dump(self, section, config):
		self.stream.write("[%s]\n" % section)
		for option in config.option_list():
			self.stream.write("%s = %s\n" % (option, getattr(config, option)))

