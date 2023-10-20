# -*- coding: utf-8 -*-

## --------------------------------------------------------------------
## Amazon S3 manager
##
## Authors   : Michal Ludvig <michal@logix.cz> (https://www.logix.cz/michal)
##             Florent Viard <florent@sodria.com> (https://www.sodria.com)
## Copyright : TGRMN Software, Sodria SAS and contributors
## License   : GPL Version 2
## Website   : https://s3tools.org
## --------------------------------------------------------------------

from __future__ import absolute_import, division

import functools
import re
import posixpath
import sys

from calendar import timegm
from hashlib import md5
from logging import debug, warning, error

import xml.dom.minidom
import xml.etree.ElementTree as ET

from .ExitCodes import EX_OSFILE

try:
    import dateutil.parser
except ImportError:
    sys.stderr.write(u"""
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
ImportError trying to import dateutil.parser.
Please install the python dateutil module:
$ sudo apt-get install python-dateutil
  or
$ sudo yum install python-dateutil
  or
$ pip install python-dateutil
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
""")
    sys.stderr.flush()
    sys.exit(EX_OSFILE)

try:
    from urllib import quote
except ImportError:
    # python 3 support
    from urllib.parse import quote

try:
    unicode = unicode
except NameError:
    # python 3 support
    # In python 3, unicode -> str, and str -> bytes
    unicode = str


__all__ = []

s3path = posixpath
__all__.append("s3path")

try:
    md5()
except ValueError as exc:
    # md5 is disabled for FIPS-compliant Python builds.
    # Since s3cmd does not use md5 in a security context,
    # it is safe to allow the use of it by setting useforsecurity to False.
    try:
        md5(usedforsecurity=False)
        md5 = functools.partial(md5, usedforsecurity=False)
    except Exception:
        # "usedforsecurity" is only available on python >= 3.9 or RHEL distributions
        raise exc
__all__.append("md5")



RE_S3_DATESTRING = re.compile('\\.[0-9]*(?:[Z\\-\\+]*?)')
RE_XML_NAMESPACE = re.compile(b'^(<?[^>]+?>\\s*|\\s*)(<\\w+) xmlns=[\'"](https?://[^\'"]+)[\'"]', re.MULTILINE)


# Date and time helpers


def dateS3toPython(date):
    # Reset milliseconds to 000
    date = RE_S3_DATESTRING.sub(".000", date)
    return dateutil.parser.parse(date, fuzzy=True)
__all__.append("dateS3toPython")


def dateS3toUnix(date):
    ## NOTE: This is timezone-aware and return the timestamp regarding GMT
    return timegm(dateS3toPython(date).utctimetuple())
__all__.append("dateS3toUnix")


def dateRFC822toPython(date):
    """
    Convert a string formatted like '2020-06-27T15:56:34Z' into a python datetime
    """
    return dateutil.parser.parse(date, fuzzy=True)
__all__.append("dateRFC822toPython")


def dateRFC822toUnix(date):
    return timegm(dateRFC822toPython(date).utctimetuple())
__all__.append("dateRFC822toUnix")


def formatDateTime(s3timestamp):
    date_obj = dateutil.parser.parse(s3timestamp, fuzzy=True)
    return date_obj.strftime("%Y-%m-%d %H:%M")
__all__.append("formatDateTime")


# Encoding / Decoding


def base_unicodise(string, encoding='UTF-8', errors='replace', silent=False):
    """
    Convert 'string' to Unicode or raise an exception.
    """
    if type(string) == unicode:
        return string

    if not silent:
        debug("Unicodising %r using %s" % (string, encoding))
    try:
        return unicode(string, encoding, errors)
    except UnicodeDecodeError:
        raise UnicodeDecodeError("Conversion to unicode failed: %r" % string)
__all__.append("base_unicodise")


def base_deunicodise(string, encoding='UTF-8', errors='replace', silent=False):
    """
    Convert unicode 'string' to <type str>, by default replacing
    all invalid characters with '?' or raise an exception.
    """
    if type(string) != unicode:
        return string

    if not silent:
        debug("DeUnicodising %r using %s" % (string, encoding))
    try:
        return string.encode(encoding, errors)
    except UnicodeEncodeError:
        raise UnicodeEncodeError("Conversion from unicode failed: %r" % string)
__all__.append("base_deunicodise")


def decode_from_s3(string, errors = "replace"):
    """
    Convert S3 UTF-8 'string' to Unicode or raise an exception.
    """
    return base_unicodise(string, "UTF-8", errors, True)
__all__.append("decode_from_s3")


def encode_to_s3(string, errors='replace'):
    """
    Convert Unicode to S3 UTF-8 'string', by default replacing
    all invalid characters with '?' or raise an exception.
    """
    return base_deunicodise(string, "UTF-8", errors, True)
__all__.append("encode_to_s3")


def s3_quote(param, quote_backslashes=True, unicode_output=False):
    """
    URI encode every byte. UriEncode() must enforce the following rules:
    - URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
    - The space character is a reserved character and must be encoded as "%20" (and not as "+").
    - Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
    - Letters in the hexadecimal value must be uppercase, for example "%1A".
    - Encode the forward slash character, '/', everywhere except in the object key name.
    For example, if the object key name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.
    """
    if quote_backslashes:
        safe_chars = "~"
    else:
        safe_chars = "~/"
    param = encode_to_s3(param)
    param = quote(param, safe=safe_chars)
    if unicode_output:
        param = decode_from_s3(param)
    else:
        param = encode_to_s3(param)
    return param
__all__.append("s3_quote")


def base_urlencode_string(string, urlencoding_mode = None, unicode_output=False):
    string = encode_to_s3(string)

    if urlencoding_mode == "verbatim":
        ## Don't do any pre-processing
        return string

    encoded = quote(string, safe="~/")
    debug("String '%s' encoded to '%s'" % (string, encoded))
    if unicode_output:
        return decode_from_s3(encoded)
    else:
        return encode_to_s3(encoded)
__all__.append("base_urlencode_string")


def base_replace_nonprintables(string, with_message=False):
    """
    replace_nonprintables(string)

    Replaces all non-printable characters 'ch' in 'string'
    where ord(ch) <= 26 with ^@, ^A, ... ^Z
    """
    new_string = ""
    modified = 0
    for c in string:
        o = ord(c)
        if (o <= 31):
            new_string += "^" + chr(ord('@') + o)
            modified += 1
        elif (o == 127):
            new_string += "^?"
            modified += 1
        else:
            new_string += c
    if modified and with_message:
        warning("%d non-printable characters replaced in: %s" % (modified, new_string))
    return new_string
__all__.append("base_replace_nonprintables")


# XML helpers


def parseNodes(nodes):
    ## WARNING: Ignores text nodes from mixed xml/text.
    ## For instance <tag1>some text<tag2>other text</tag2></tag1>
    ## will be ignore "some text" node
    ## WARNING 2: Any node at first level without children will also be ignored
    retval = []
    for node in nodes:
        retval_item = {}
        for child in node:
            name = decode_from_s3(child.tag)
            if len(child):
                retval_item[name] = parseNodes([child])
            else:
                found_text = node.findtext(".//%s" % child.tag)
                if found_text is not None:
                    retval_item[name] = decode_from_s3(found_text)
                else:
                    retval_item[name] = None
        if retval_item:
            retval.append(retval_item)
    return retval
__all__.append("parseNodes")


def getPrettyFromXml(xmlstr):
    xmlparser = xml.dom.minidom.parseString(xmlstr)
    return xmlparser.toprettyxml()

__all__.append("getPrettyFromXml")


def stripNameSpace(xml):
    """
    removeNameSpace(xml) -- remove top-level AWS namespace
    Operate on raw byte(utf-8) xml string. (Not unicode)
    """
    xmlns_match = RE_XML_NAMESPACE.match(xml)
    if xmlns_match:
        xmlns = xmlns_match.group(3)
        xml = RE_XML_NAMESPACE.sub(b"\\1\\2", xml, 1)
    else:
        xmlns = None
    return xml, xmlns
__all__.append("stripNameSpace")


def getTreeFromXml(xml):
    xml, xmlns = stripNameSpace(encode_to_s3(xml))
    try:
        tree = ET.fromstring(xml)
        if xmlns:
            tree.attrib['xmlns'] = xmlns
        return tree
    except Exception as e:
        error("Error parsing xml: %s", e)
        error(xml)
        raise
__all__.append("getTreeFromXml")


def getListFromXml(xml, node):
    tree = getTreeFromXml(xml)
    nodes = tree.findall('.//%s' % (node))
    return parseNodes(nodes)
__all__.append("getListFromXml")


def getDictFromTree(tree):
    ret_dict = {}
    for child in tree:
        if len(child):
            ## Complex-type child. Recurse
            content = getDictFromTree(child)
        else:
            content = decode_from_s3(child.text) if child.text is not None else None
        child_tag = decode_from_s3(child.tag)
        if child_tag in ret_dict:
            if not type(ret_dict[child_tag]) == list:
                ret_dict[child_tag] = [ret_dict[child_tag]]
            ret_dict[child_tag].append(content or "")
        else:
            ret_dict[child_tag] = content or ""
    return ret_dict
__all__.append("getDictFromTree")


def getTextFromXml(xml, xpath):
    tree = getTreeFromXml(xml)
    if tree.tag.endswith(xpath):
        return decode_from_s3(tree.text) if tree.text is not None else None
    else:
        result = tree.findtext(xpath)
        return decode_from_s3(result) if result is not None else None
__all__.append("getTextFromXml")


def getRootTagName(xml):
    tree = getTreeFromXml(xml)
    return decode_from_s3(tree.tag) if tree.tag is not None else None
__all__.append("getRootTagName")


def xmlTextNode(tag_name, text):
    el = ET.Element(tag_name)
    el.text = decode_from_s3(text)
    return el
__all__.append("xmlTextNode")


def appendXmlTextNode(tag_name, text, parent):
    """
    Creates a new <tag_name> Node and sets
    its content to 'text'. Then appends the
    created Node to 'parent' element if given.
    Returns the newly created Node.
    """
    el = xmlTextNode(tag_name, text)
    parent.append(el)
    return el
__all__.append("appendXmlTextNode")


# vim:et:ts=4:sts=4:ai
