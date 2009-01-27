## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import os
import time
import re
import string
import random
import rfc822
try:
	from hashlib import md5
except ImportError:
	from md5 import md5
import errno

from logging import debug, info, warning, error

import Config

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

def parseNodes(nodes):
	## WARNING: Ignores text nodes from mixed xml/text.
	## For instance <tag1>some text<tag2>other text</tag2></tag1>
	## will be ignore "some text" node
	retval = []
	for node in nodes:
		retval_item = {}
		for child in node.getchildren():
			name = child.tag
			if child.getchildren():
				retval_item[name] = parseNodes([child])
			else:
				retval_item[name] = node.findtext(".//%s" % child.tag)
		retval.append(retval_item)
	return retval

def stripNameSpace(xml):
	"""
	removeNameSpace(xml) -- remove top-level AWS namespace
	"""
	r = re.compile('^(<?[^>]+?>\s?)(<\w+) xmlns=[\'"](http://[^\'"]+)[\'"](.*)', re.MULTILINE)
	if r.match(xml):
		xmlns = r.match(xml).groups()[2]
		xml = r.sub("\\1\\2\\4", xml)
	else:
		xmlns = None
	return xml, xmlns

def getTreeFromXml(xml):
	xml, xmlns = stripNameSpace(xml)
	tree = ET.fromstring(xml)
	if xmlns:
		tree.attrib['xmlns'] = xmlns
	return tree
	
def getListFromXml(xml, node):
	tree = getTreeFromXml(xml)
	nodes = tree.findall('.//%s' % (node))
	return parseNodes(nodes)

def getDictFromTree(tree):
	ret_dict = {}
	for child in tree.getchildren():
		if child.getchildren():
			## Complex-type child. We're not interested
			continue
		if ret_dict.has_key(child.tag):
			if not type(ret_dict[child.tag]) == list:
				ret_dict[child.tag] = [ret_dict[child.tag]]
			ret_dict[child.tag].append(child.text or "")
		else:
			ret_dict[child.tag] = child.text or ""
	return ret_dict

def getTextFromXml(xml, xpath):
	tree = getTreeFromXml(xml)
	if tree.tag.endswith(xpath):
		return tree.text
	else:
		return tree.findtext(xpath)

def getRootTagName(xml):
	tree = getTreeFromXml(xml)
	return tree.tag

def xmlTextNode(tag_name, text):
	el = ET.Element(tag_name)
	el.text = unicode(text)
	return el

def appendXmlTextNode(tag_name, text, parent):
	"""
	Creates a new <tag_name> Node and sets
	its content to 'text'. Then appends the
	created Node to 'parent' element if given.
	Returns the newly created Node.
	"""
	parent.append(xmlTextNode(tag_name, text))

def dateS3toPython(date):
	date = re.compile("\.\d\d\dZ").sub(".000Z", date)
	return time.strptime(date, "%Y-%m-%dT%H:%M:%S.000Z")

def dateS3toUnix(date):
	## FIXME: This should be timezone-aware.
	## Currently the argument to strptime() is GMT but mktime() 
	## treats it as "localtime". Anyway...
	return time.mktime(dateS3toPython(date))

def dateRFC822toPython(date):
	return rfc822.parsedate(date)

def dateRFC822toUnix(date):
	return time.mktime(dateRFC822toPython(date))

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
	h = md5()
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

	if type(string) == unicode:
		return string
	debug("Unicodising %r using %s" % (string, encoding))
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

	if type(string) != unicode:
		return str(string)
	debug("DeUnicodising %r using %s" % (string, encoding))
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

