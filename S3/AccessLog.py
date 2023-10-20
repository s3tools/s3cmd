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

from . import S3Uri
from .Exceptions import ParameterError
from .BaseUtils import getTreeFromXml, decode_from_s3
from .ACL import GranteeAnonRead

try:
    import xml.etree.ElementTree as ET
except ImportError:
    import elementtree.ElementTree as ET

PY3 = (sys.version_info >= (3,0))

__all__ = []
class AccessLog(object):
    LOG_DISABLED = "<BucketLoggingStatus></BucketLoggingStatus>"
    LOG_TEMPLATE = "<LoggingEnabled><TargetBucket></TargetBucket><TargetPrefix></TargetPrefix></LoggingEnabled>"

    def __init__(self, xml = None):
        if not xml:
            xml = self.LOG_DISABLED
        self.tree = getTreeFromXml(xml)
        self.tree.attrib['xmlns'] = "http://doc.s3.amazonaws.com/2006-03-01"

    def isLoggingEnabled(self):
        return (self.tree.find(".//LoggingEnabled") is not None)

    def disableLogging(self):
        el = self.tree.find(".//LoggingEnabled")
        if el:
            self.tree.remove(el)

    def enableLogging(self, target_prefix_uri):
        el = self.tree.find(".//LoggingEnabled")
        if not el:
            el = getTreeFromXml(self.LOG_TEMPLATE)
            self.tree.append(el)
        el.find(".//TargetBucket").text = target_prefix_uri.bucket()
        el.find(".//TargetPrefix").text = target_prefix_uri.object()

    def targetPrefix(self):
        if self.isLoggingEnabled():
            target_prefix = u"s3://%s/%s" % (
                self.tree.find(".//LoggingEnabled//TargetBucket").text,
                self.tree.find(".//LoggingEnabled//TargetPrefix").text)
            return S3Uri.S3Uri(target_prefix)
        else:
            return ""

    def setAclPublic(self, acl_public):
        le = self.tree.find(".//LoggingEnabled")
        if le is None:
            raise ParameterError("Logging not enabled, can't set default ACL for logs")
        tg = le.find(".//TargetGrants")
        if not acl_public:
            if not tg:
                ## All good, it's not been there
                return
            else:
                le.remove(tg)
        else: # acl_public == True
            anon_read = GranteeAnonRead().getElement()
            if not tg:
                tg = ET.SubElement(le, "TargetGrants")
            ## What if TargetGrants already exists? We should check if
            ## AnonRead is there before appending a new one. Later...
            tg.append(anon_read)

    def isAclPublic(self):
        raise NotImplementedError()

    def __unicode__(self):
        return decode_from_s3(ET.tostring(self.tree))

    def __str__(self):
        if PY3:
            # Return unicode
            return ET.tostring(self.tree, encoding="unicode")
        else:
            # Return bytes
            return ET.tostring(self.tree)

__all__.append("AccessLog")

if __name__ == "__main__":
    log = AccessLog()
    print(log)
    log.enableLogging(S3Uri.S3Uri(u"s3://targetbucket/prefix/log-"))
    print(log)
    log.setAclPublic(True)
    print(log)
    log.setAclPublic(False)
    print(log)
    log.disableLogging()
    print(log)

# vim:et:ts=4:sts=4:ai
