## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import os
import time
import re
import string
import random
try:
	import hashlib as hash
except ImportError:
	import md5 as hash
import errno

from logging import debug, info, warning, error

import Config

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

def stripTagXmlns(xmlns, tag):
	"""
	Returns a function that, given a tag name argument, removes
	eventual ElementTree xmlns from it.

	Example:
		stripTagXmlns("{myXmlNS}tag") -> "tag"
	"""
	if not xmlns:
		return tag
	return re.sub(xmlns, "", tag)

def fixupXPath(xmlns, xpath, max = 0):
	if not xmlns:
		return xpath
	retval = re.subn("//", "//%s" % xmlns, xpath, max)[0]
	return retval

def parseNodes(nodes, xmlns = ""):
	## WARNING: Ignores text nodes from mixed xml/text.
	## For instance <tag1>some text<tag2>other text</tag2></tag1>
	## will be ignore "some text" node
	retval = []
	for node in nodes:
		retval_item = {}
		for child in node.getchildren():
			name = stripTagXmlns(xmlns, child.tag)
			if child.getchildren():
				retval_item[name] = parseNodes([child], xmlns)
			else:
				retval_item[name] = node.findtext(".//%s" % child.tag)
		retval.append(retval_item)
	return retval

def getNameSpace(element):
	if not element.tag.startswith("{"):
		return ""
	return re.compile("^(\{[^}]+\})").match(element.tag).groups()[0]

def getTreeFromXml(xml):
	tree = ET.fromstring(xml)
	tree.xmlns = getNameSpace(tree)
	return tree
	
def getListFromXml(xml, node):
	tree = getTreeFromXml(xml)
	nodes = tree.findall('.//%s%s' % (tree.xmlns, node))
	return parseNodes(nodes, tree.xmlns)
	
def getTextFromXml(xml, xpath):
	tree = getTreeFromXml(xml)
	if tree.tag.endswith(xpath):
		return tree.text
	else:
		return tree.findtext(fixupXPath(tree.xmlns, xpath))

def getRootTagName(xml):
	tree = getTreeFromXml(xml)
	return stripTagXmlns(tree.xmlns, tree.tag)

def dateS3toPython(date):
	date = re.compile("\.\d\d\dZ").sub(".000Z", date)
	return time.strptime(date, "%Y-%m-%dT%H:%M:%S.000Z")

def dateS3toUnix(date):
	## FIXME: This should be timezone-aware.
	## Currently the argument to strptime() is GMT but mktime() 
	## treats it as "localtime". Anyway...
	return time.mktime(dateS3toPython(date))

def formatSize(size, human_readable = False, floating_point = False):
	size = floating_point and float(size) or int(size)
	if human_readable:
		coeffs = ['k', 'M', 'G', 'T']
		coeff = ""
		while size > 2048:
			size /= 1024
			coeff = coeffs.pop(0)
		return (size, coeff)
	else:
		return (size, "")

def formatDateTime(s3timestamp):
	return time.strftime("%Y-%m-%d %H:%M", dateS3toPython(s3timestamp))

def convertTupleListToDict(list):
	retval = {}
	for tuple in list:
		retval[tuple[0]] = tuple[1]
	return retval


_rnd_chars = string.ascii_letters+string.digits
_rnd_chars_len = len(_rnd_chars)
def rndstr(len):
	retval = ""
	while len > 0:
		retval += _rnd_chars[random.randint(0, _rnd_chars_len-1)]
		len -= 1
	return retval

def mktmpsomething(prefix, randchars, createfunc):
	old_umask = os.umask(0077)
	tries = 5
	while tries > 0:
		dirname = prefix + rndstr(randchars)
		try:
			createfunc(dirname)
			break
		except OSError, e:
			if e.errno != errno.EEXIST:
				os.umask(old_umask)
				raise
		tries -= 1

	os.umask(old_umask)
	return dirname

def mktmpdir(prefix = "/tmp/tmpdir-", randchars = 10):
	return mktmpsomething(prefix, randchars, os.mkdir)

def mktmpfile(prefix = "/tmp/tmpfile-", randchars = 20):
	createfunc = lambda filename : os.close(os.open(filename, os.O_CREAT | os.O_EXCL))
	return mktmpsomething(prefix, randchars, createfunc)

def hash_file_md5(filename):
	h = hash.md5()
	f = open(filename, "rb")
	while True:
		# Hash 32kB chunks
		data = f.read(32*1024)
		if not data:
			break
		h.update(data)
	f.close()
	return h.hexdigest()

def mkdir_with_parents(dir_name):
	"""
	mkdir_with_parents(dst_dir)
	
	Create directory 'dir_name' with all parent directories

	Returns True on success, False otherwise.
	"""
	pathmembers = dir_name.split(os.sep)
	tmp_stack = []
	while pathmembers and not os.path.isdir(os.sep.join(pathmembers)):
		tmp_stack.append(pathmembers.pop())
	while tmp_stack:
		pathmembers.append(tmp_stack.pop())
		cur_dir = os.sep.join(pathmembers)
		try:
			debug("mkdir(%s)" % cur_dir)
			os.mkdir(cur_dir)
		except (OSError, IOError), e:
			warning("%s: can not make directory: %s" % (cur_dir, e.strerror))
			return False
		except Exception, e:
			warning("%s: %s" % (cur_dir, e))
			return False
	return True

def unicodise(string, encoding = None, errors = "replace"):
	"""
	Convert 'string' to Unicode or raise an exception.
	"""

	if not encoding:
		encoding = Config.Config().encoding

	debug("Unicodising %r using %s" % (string, encoding))
	if type(string) == unicode:
		return string
	try:
		return string.decode(encoding, errors)
	except UnicodeDecodeError:
		raise UnicodeDecodeError("Conversion to unicode failed: %r" % string)

def deunicodise(string, encoding = None, errors = "replace"):
	"""
	Convert unicode 'string' to <type str>, by default replacing
	all invalid characters with '?' or raise an exception.
	"""

	if not encoding:
		encoding = Config.Config().encoding

	debug("DeUnicodising %r using %s" % (string, encoding))
	if type(string) != unicode:
		return str(string)
	try:
		return string.encode(encoding, errors)
	except UnicodeEncodeError:
		raise UnicodeEncodeError("Conversion from unicode failed: %r" % string)

def unicodise_safe(string, encoding = None):
	"""
	Convert 'string' to Unicode according to current encoding 
	and replace all invalid characters with '?'
	"""

	return unicodise(deunicodise(string, encoding), encoding).replace(u'\ufffd', '?')

