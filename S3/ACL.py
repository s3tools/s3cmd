# -*- coding: utf-8 -*-

## --------------------------------------------------------------------
## Amazon S3 - Access Control List representation
##
## Authors   : Michal Ludvig <michal@logix.cz> (https://www.logix.cz/michal)
##             Florent Viard <florent@sodria.com> (https://www.sodria.com)
## Copyright : TGRMN Software, Sodria SAS and contributors
## License   : GPL Version 2
## Website   : https://s3tools.org
## --------------------------------------------------------------------

from __future__ import absolute_import, print_function

import sys
from .BaseUtils import getTreeFromXml, encode_to_s3, decode_from_s3
from .Utils import deunicodise

try:
    import xml.etree.ElementTree as ET
except ImportError:
    import elementtree.ElementTree as ET

PY3 = (sys.version_info >= (3, 0))

class Grantee(object):
    ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
    LOG_DELIVERY_URI = "http://acs.amazonaws.com/groups/s3/LogDelivery"

    def __init__(self):
        self.xsi_type = None
        self.tag = None
        self.name = None
        self.display_name = ''
        self.permission = None

    def __repr__(self):
        return repr('Grantee("%(tag)s", "%(name)s", "%(permission)s")' % {
            "tag" : self.tag,
            "name" : self.name,
            "permission" : self.permission
        })

    def isAllUsers(self):
        return self.tag == "URI" and self.name == Grantee.ALL_USERS_URI

    def isAnonRead(self):
        return self.isAllUsers() and (self.permission == "READ" or self.permission == "FULL_CONTROL")

    def isAnonWrite(self):
        return self.isAllUsers() and (self.permission == "WRITE" or self.permission == "FULL_CONTROL")

    def getElement(self):
        el = ET.Element("Grant")
        grantee = ET.SubElement(el, "Grantee", {
            'xmlns:xsi' : 'http://www.w3.org/2001/XMLSchema-instance',
            'xsi:type' : self.xsi_type
        })
        name = ET.SubElement(grantee, self.tag)
        name.text = self.name
        permission = ET.SubElement(el, "Permission")
        permission.text = self.permission
        return el

class GranteeAnonRead(Grantee):
    def __init__(self):
        Grantee.__init__(self)
        self.xsi_type = "Group"
        self.tag = "URI"
        self.name = Grantee.ALL_USERS_URI
        self.permission = "READ"

class GranteeLogDelivery(Grantee):
    def __init__(self, permission):
        """
        permission must be either READ_ACP or WRITE
        """
        Grantee.__init__(self)
        self.xsi_type = "Group"
        self.tag = "URI"
        self.name = Grantee.LOG_DELIVERY_URI
        self.permission = permission

class ACL(object):
    EMPTY_ACL = b"<AccessControlPolicy><Owner><ID></ID></Owner><AccessControlList></AccessControlList></AccessControlPolicy>"

    def __init__(self, xml = None):
        if not xml:
            xml = ACL.EMPTY_ACL

        self.grantees = []
        self.owner_id = ""
        self.owner_nick = ""

        tree = getTreeFromXml(encode_to_s3(xml))
        self.parseOwner(tree)
        self.parseGrants(tree)

    def parseOwner(self, tree):
        self.owner_id = tree.findtext(".//Owner//ID")
        self.owner_nick = tree.findtext(".//Owner//DisplayName")

    def parseGrants(self, tree):
        for grant in tree.findall(".//Grant"):
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
            self.grantees.append(grantee)

    def getGrantList(self):
        acl = []
        for grantee in self.grantees:
            if grantee.display_name:
                user = grantee.display_name
            elif grantee.isAllUsers():
                user = "*anon*"
            else:
                user = grantee.name
            acl.append({'grantee': user, 'permission': grantee.permission})
        return acl

    def getOwner(self):
        return { 'id' : self.owner_id, 'nick' : self.owner_nick }

    def isAnonRead(self):
        for grantee in self.grantees:
            if grantee.isAnonRead():
                return True
        return False

    def isAnonWrite(self):
        for grantee in self.grantees:
            if grantee.isAnonWrite():
                return True
        return False

    def grantAnonRead(self):
        if not self.isAnonRead():
            self.appendGrantee(GranteeAnonRead())

    def revokeAnonRead(self):
        self.grantees = [g for g in self.grantees if not g.isAnonRead()]

    def revokeAnonWrite(self):
        self.grantees = [g for g in self.grantees if not g.isAnonWrite()]

    def appendGrantee(self, grantee):
        self.grantees.append(grantee)

    def hasGrant(self, name, permission):
        name = name.lower()
        permission = permission.upper()

        for grantee in self.grantees:
            if grantee.name.lower() == name:
                if grantee.permission == "FULL_CONTROL":
                    return True
                elif grantee.permission.upper() == permission:
                    return True

        return False

    def grant(self, name, permission):
        if self.hasGrant(name, permission):
            return

        permission = permission.upper()

        if "ALL" == permission:
            permission = "FULL_CONTROL"

        if "FULL_CONTROL" == permission:
            self.revoke(name, "ALL")

        grantee = Grantee()
        grantee.name = name
        grantee.permission = permission

        if  '@' in name:
            grantee.name = grantee.name.lower()
            grantee.xsi_type = "AmazonCustomerByEmail"
            grantee.tag = "EmailAddress"
        elif 'http://acs.amazonaws.com/groups/' in name:
            grantee.xsi_type = "Group"
            grantee.tag = "URI"
        else:
            grantee.name = grantee.name.lower()
            grantee.xsi_type = "CanonicalUser"
            grantee.tag = "ID"

        self.appendGrantee(grantee)


    def revoke(self, name, permission):
        name = name.lower()
        permission = permission.upper()

        if "ALL" == permission:
            self.grantees = [g for g in self.grantees if not (g.name.lower() == name or (g.display_name is not None and g.display_name.lower() == name))]
        else:
            self.grantees = [g for g in self.grantees if not (((g.display_name is not None and g.display_name.lower() == name) or g.name.lower() == name)
                and g.permission.upper() == permission)]

    def get_printable_tree(self):
        tree = getTreeFromXml(ACL.EMPTY_ACL)
        tree.attrib['xmlns'] = "http://s3.amazonaws.com/doc/2006-03-01/"
        owner = tree.find(".//Owner//ID")
        owner.text = self.owner_id
        acl = tree.find(".//AccessControlList")
        for grantee in self.grantees:
            acl.append(grantee.getElement())
        return tree

    def __unicode__(self):
        return decode_from_s3(ET.tostring(self.get_printable_tree()))

    def __str__(self):
        if PY3:
            # Return unicode
            return ET.tostring(self.get_printable_tree(), encoding="unicode")
        else:
            # Return bytes
            return ET.tostring(self.get_printable_tree())

if __name__ == "__main__":
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
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
    print("Grants:", acl.getGrantList())
    acl.revokeAnonRead()
    print("Grants:", acl.getGrantList())
    acl.grantAnonRead()
    print("Grants:", acl.getGrantList())
    print(acl)

# vim:et:ts=4:sts=4:ai
