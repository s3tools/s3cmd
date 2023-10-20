# -*- coding: utf-8 -*-

## --------------------------------------------------------------------
## Amazon S3 manager - Exceptions library
##
## Authors   : Michal Ludvig <michal@logix.cz> (https://www.logix.cz/michal)
##             Florent Viard <florent@sodria.com> (https://www.sodria.com)
## Copyright : TGRMN Software, Sodria SAS and contributors
## License   : GPL Version 2
## Website   : https://s3tools.org
## --------------------------------------------------------------------

from __future__ import absolute_import

from logging import debug, error
import sys
import S3.BaseUtils
import S3.Utils
from . import ExitCodes

if sys.version_info >= (3, 0):
    PY3 = True
    # In python 3, unicode -> str, and str -> bytes
    unicode = str
else:
    PY3 = False

## External exceptions

from ssl import SSLError as S3SSLError

try:
    from ssl import CertificateError as S3SSLCertificateError
except ImportError:
    class S3SSLCertificateError(Exception):
        pass


try:
    from xml.etree.ElementTree import ParseError as XmlParseError
except ImportError:
    # ParseError was only added in python2.7, before ET was raising ExpatError
    from xml.parsers.expat import ExpatError as XmlParseError


## s3cmd exceptions

class S3Exception(Exception):
    def __init__(self, message=""):
        self.message = S3.Utils.unicodise(message)

    def __str__(self):
        ## Don't return self.message directly because
        ## __unicode__() method could be overridden in subclasses!
        if PY3:
            return self.__unicode__()
        else:
            return S3.Utils.deunicodise(self.__unicode__())

    def __unicode__(self):
        return self.message

    ## (Base)Exception.message has been deprecated in Python 2.6
    def _get_message(self):
        return self._message

    def _set_message(self, message):
        self._message = message
    message = property(_get_message, _set_message)


class S3Error(S3Exception):
    def __init__(self, response):
        self.status = response["status"]
        self.reason = response["reason"]
        self.info = {
            "Code": "",
            "Message": "",
            "Resource": ""
        }
        debug("S3Error: %s (%s)" % (self.status, self.reason))
        if "headers" in response:
            for header in response["headers"]:
                debug("HttpHeader: %s: %s" % (header, response["headers"][header]))
        if "data" in response and response["data"]:
            try:
                tree = S3.BaseUtils.getTreeFromXml(response["data"])
            except XmlParseError:
                debug("Not an XML response")
            else:
                try:
                    self.info.update(self.parse_error_xml(tree))
                except Exception as e:
                    error("Error parsing xml: %s.  ErrorXML: %s" % (e, response["data"]))

        self.code = self.info["Code"]
        self.message = self.info["Message"]
        self.resource = self.info["Resource"]

    def __unicode__(self):
        retval = u"%d " % (self.status)
        retval += (u"(%s)" % (self.code or self.reason))
        error_msg = self.message
        if error_msg:
            retval += (u": %s" % error_msg)
        return retval

    def get_error_code(self):
        if self.status in [301, 307]:
            return ExitCodes.EX_SERVERMOVED
        elif self.status in [400, 405, 411, 416, 417, 501, 504]:
            return ExitCodes.EX_SERVERERROR
        elif self.status == 403:
            return ExitCodes.EX_ACCESSDENIED
        elif self.status == 404:
            return ExitCodes.EX_NOTFOUND
        elif self.status == 409:
            return ExitCodes.EX_CONFLICT
        elif self.status == 412:
            return ExitCodes.EX_PRECONDITION
        elif self.status == 500:
            return ExitCodes.EX_SOFTWARE
        elif self.status in [429, 503]:
            return ExitCodes.EX_SERVICE
        else:
            return ExitCodes.EX_SOFTWARE

    @staticmethod
    def parse_error_xml(tree):
        info = {}
        error_node = tree
        if not error_node.tag == "Error":
            error_node = tree.find(".//Error")
        if error_node is not None:
            for child in error_node:
                if child.text != "":
                    debug("ErrorXML: " + child.tag + ": " + repr(child.text))
                    info[child.tag] = child.text
        else:
            raise S3ResponseError("Malformed error XML returned from remote server.")
        return info


class CloudFrontError(S3Error):
    pass

class S3UploadError(S3Exception):
    pass

class S3DownloadError(S3Exception):
    pass

class S3RequestError(S3Exception):
    pass

class S3ResponseError(S3Exception):
    pass

class InvalidFileError(S3Exception):
    pass

class ParameterError(S3Exception):
    pass

# vim:et:ts=4:sts=4:ai
