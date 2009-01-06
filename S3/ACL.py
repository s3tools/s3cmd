## Amazon S3 - Access Control List representation
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

from Utils import *

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

class Grantee(object):
	ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"

	xsi_type = None
	tag = None
	name = None
	display_name = None
	permission = None

	def __str__(self):
		return '%(name)s : %(permission)s' % { "name" : self.name, "permission" : self.permission }

	def isAllUsers(self):
		return self.tag == "URI" and self.name == Grantee.ALL_USERS_URI
	
	def isAnonRead(self):
		return self.isAllUsers and self.permission == "READ"

class GranteeAnonRead(Grantee):
	xsi_type = "Group"
	tag = "URI"
	name = Grantee.ALL_USERS_URI
	permission = "READ"

class ACL(object):
	EMPTY_ACL = """
	<AccessControlPolicy>
		<AccessControlList>
		</AccessControlList>
	</AccessControlPolicy>
	"""

	grants = []

	def __init__(self, xml = None):
		if not xml:
			xml = ACL.EMPTY_ACL
		self.tree = getTreeFromXml(xml)
		self.grants = self.parseGrants()
	
	def parseGrants(self):
		for grant in self.tree.findall(".//Grant"):
			grantee = Grantee()
			g = grant.find(".//Grantee")
			grantee.xsi_type = g.attrib['{http://www.w3.org/2001/XMLSchema-instance}type']
			grantee.permission = grant.find('Permission').text
			for el in g:
				if el.tag == "DisplayName":
					grantee.display_name = el.text
				else:
					grantee.tag = el.tag
					grantee.name = el.text
			self.grants.append(grantee)
		return self.grants

	def getGrantList(self):
		acl = {}
		for grantee in self.grants:
			if grantee.display_name:
				user = grantee.display_name
			elif grantee.isAllUsers():
				user = "*anon*"
			else:
				user = grantee.name
			acl[user] = grantee.permission
		return acl

	def isAnonRead(self):
		for grantee in self.grants:
			if grantee.isAnonRead():
				return True
		return False
	
	def grantAnonRead(self):
		if not self.isAnonRead():
			self.grants.append(GranteeAnonRead())
	
	def revokeAnonRead(self):
		self.grants = [g for g in self.grants if not g.isAnonRead()]

	def __str__(self):
		return ET.tostring(self.tree)

if __name__ == "__main__":
	xml = """<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner>
	<ID>12345678901234567890</ID>
	<DisplayName>owner-nickname</DisplayName>
</Owner>
<AccessControlList>
	<Grant>
		<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
			<ID>12345678901234567890</ID>
			<DisplayName>owner-nickname</DisplayName>
		</Grantee>
		<Permission>FULL_CONTROL</Permission>
	</Grant>
	<Grant>
		<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
			<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
		</Grantee>
		<Permission>READ</Permission>
	</Grant>
</AccessControlList>
</AccessControlPolicy>
	"""
	acl = ACL(xml)
	print "Grants:", acl.getGrantList()
	acl.revokeAnonRead()
	print "Grants:", acl.getGrantList()
	acl.grantAnonRead()
	print "Grants:", acl.getGrantList()
	#print acl
