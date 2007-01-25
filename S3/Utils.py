## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import time
import re
import elementtree.ElementTree as ET

def parseNodes(nodes, xmlns = ""):
	retval = []
	for node in nodes:
		retval_item = {}
		if xmlns != "":
			## Take regexp compilation out of the loop
			r = re.compile(xmlns)
			fixup = lambda string : r.sub("", string)
		else:
			## Do-nothing function
			fixup = lambda string : string

		for child in node.getchildren():
			name = fixup(child.tag)
			retval_item[name] = node.findtext(".//%s" % child.tag)

		retval.append(retval_item)
	return retval

def getNameSpace(element):
	if not element.tag.startswith("{"):
		return ""
	return re.compile("^(\{[^}]+\})").match(element.tag).groups()[0]

def getListFromXml(xml, node):
	tree = ET.fromstring(xml)
	xmlns = getNameSpace(tree)
	nodes = tree.findall('.//%s%s' % (xmlns, node))
	return parseNodes(nodes, xmlns)
	
def dateS3toPython(date):
	date = re.compile("\.\d\d\dZ").sub(".000Z", date)
	return time.strptime(date, "%Y-%m-%dT%H:%M:%S.000Z")

def dateS3toUnix(date):
	## FIXME: This should be timezone-aware.
	## Currently the argument to strptime() is GMT but mktime() 
	## treats it as "localtime". Anyway...
	return time.mktime(dateS3toPython(date))

def formatSize(size, human_readable = False):
	size = int(size)
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

