## Amazon S3 - Access Control List representation
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

from Utils import *

try:
	import xml.etree.ElementTree as ET
except ImportError:
	import elementtree.ElementTree as ET

class ACL(object):
	EMPTY_ACL = """
	<AccessControlPolicy>
		<AccessControlList>
		</AccessControlList>
	</AccessControlPolicy>
	"""
	GRANT_PUBLIC_READ = """
	<Grant>
		<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
			<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
		</Grantee>
		<Permission>READ</Permission>
	</Grant>
	"""
	def __init__(self, xml = None):
		if not xml:
			xml = ACL.EMPTY_ACL
		self.tree = getTreeFromXml(xml)
	
	def getGrants(self):
		acl = {}
		for grant in self.tree.findall(".//Grant"):
			grantee = grant.find(".//Grantee")
			grantee = dict([(tag.tag, tag.text) for tag in grant.find(".//Grantee")])
			if grantee.has_key('DisplayName'):
				user = grantee['DisplayName']
			elif grantee.has_key('URI'):
				user = grantee['URI']
				if user == 'http://acs.amazonaws.com/groups/global/AllUsers':
					user = "*anon*"
			else:
				user = grantee[grantee.keys()[0]]
			acl[user] = grant.find('Permission').text
		return acl

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
	print acl.getGrants()
