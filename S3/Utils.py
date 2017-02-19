# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import absolute_import, division

import os
import sys
import time
import re
import string
import random
import errno
from calendar import timegm
from logging import debug, warning, error
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
    unicode
except NameError:
    # python 3 support
    # In python 3, unicode -> str, and str -> bytes
    unicode = str

import S3.Config
import S3.Exceptions
import xml.dom.minidom

from hashlib import md5

import xml.etree.ElementTree as ET

__all__ = []
def parseNodes(nodes):
    ## WARNING: Ignores text nodes from mixed xml/text.
    ## For instance <tag1>some text<tag2>other text</tag2></tag1>
    ## will be ignore "some text" node
    retval = []
    for node in nodes:
        retval_item = {}
        for child in node.getchildren():
            name = decode_from_s3(child.tag)
            if child.getchildren():
                retval_item[name] = parseNodes([child])
            else:
                found_text = node.findtext(".//%s" % child.tag)
                if found_text is not None:
                    retval_item[name] = decode_from_s3(found_text)
                else:
                    retval_item[name] = None
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
    r = re.compile(b'^(<?[^>]+?>\s*)(<\w+) xmlns=[\'"](http://[^\'"]+)[\'"](.*)', re.MULTILINE)
    if r.match(xml):
        xmlns = r.match(xml).groups()[2]
        xml = r.sub("\\1\\2\\4", xml)
    else:
        xmlns = None
    return xml, xmlns
__all__.append("stripNameSpace")

def getTreeFromXml(xml):
    xml, xmlns = stripNameSpace(xml)
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
    for child in tree.getchildren():
        if child.getchildren():
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

def dateS3toPython(date):
    # Reset milliseconds to 000
    date = re.compile('\.[0-9]*(?:[Z\\-\\+]*?)').sub(".000", date)
    return dateutil.parser.parse(date, fuzzy=True)
__all__.append("dateS3toPython")

def dateS3toUnix(date):
    ## NOTE: This is timezone-aware and return the timestamp regarding GMT
    return timegm(dateS3toPython(date).utctimetuple())
__all__.append("dateS3toUnix")

def dateRFC822toPython(date):
    return dateutil.parser.parse(date, fuzzy=True)
__all__.append("dateRFC822toPython")

def dateRFC822toUnix(date):
    return timegm(dateRFC822toPython(date).utctimetuple())
__all__.append("dateRFC822toUnix")

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
__all__.append("formatSize")

def formatDateTime(s3timestamp):
    date_obj = dateutil.parser.parse(s3timestamp, fuzzy=True)
    return date_obj.strftime("%Y-%m-%d %H:%M")
__all__.append("formatDateTime")

def convertHeaderTupleListToDict(list):
    """
    Header keys are always in lowercase in python2 but not in python3.
    """
    retval = {}
    for tuple in list:
        retval[tuple[0].lower()] = tuple[1]
    return retval
__all__.append("convertHeaderTupleListToDict")

_rnd_chars = string.ascii_letters+string.digits
_rnd_chars_len = len(_rnd_chars)
def rndstr(len):
    retval = ""
    while len > 0:
        retval += _rnd_chars[random.randint(0, _rnd_chars_len-1)]
        len -= 1
    return retval
__all__.append("rndstr")

def mktmpsomething(prefix, randchars, createfunc):
    old_umask = os.umask(0o077)
    tries = 5
    while tries > 0:
        dirname = prefix + rndstr(randchars)
        try:
            createfunc(dirname)
            break
        except OSError as e:
            if e.errno != errno.EEXIST:
                os.umask(old_umask)
                raise
        tries -= 1

    os.umask(old_umask)
    return dirname
__all__.append("mktmpsomething")

def mktmpdir(prefix = os.getenv('TMP','/tmp') + "/tmpdir-", randchars = 10):
    return mktmpsomething(prefix, randchars, os.mkdir)
__all__.append("mktmpdir")

def mktmpfile(prefix = os.getenv('TMP','/tmp') + "/tmpfile-", randchars = 20):
    createfunc = lambda filename : os.close(os.open(deunicodise(filename), os.O_CREAT | os.O_EXCL))
    return mktmpsomething(prefix, randchars, createfunc)
__all__.append("mktmpfile")

def hash_file_md5(filename):
    h = md5()
    f = open(deunicodise(filename), "rb")
    while True:
        # Hash 32kB chunks
        data = f.read(32*1024)
        if not data:
            break
        h.update(data)
    f.close()
    return h.hexdigest()
__all__.append("hash_file_md5")

def mkdir_with_parents(dir_name):
    """
    mkdir_with_parents(dst_dir)

    Create directory 'dir_name' with all parent directories

    Returns True on success, False otherwise.
    """
    pathmembers = dir_name.split(os.sep)
    tmp_stack = []
    while pathmembers and not os.path.isdir(deunicodise(os.sep.join(pathmembers))):
        tmp_stack.append(pathmembers.pop())
    while tmp_stack:
        pathmembers.append(tmp_stack.pop())
        cur_dir = os.sep.join(pathmembers)
        try:
            debug("mkdir(%s)" % cur_dir)
            os.mkdir(deunicodise(cur_dir))
        except (OSError, IOError) as e:
            debug("Can not make directory '%s' (Reason: %s)" % (cur_dir, e.strerror))
            return False
        except Exception as e:
            debug("Can not make directory '%s' (Reason: %s)" % (cur_dir, e))
            return False
    return True
__all__.append("mkdir_with_parents")

def unicodise(string, encoding = None, errors = "replace", silent=False):
    """
    Convert 'string' to Unicode or raise an exception.
    """

    if not encoding:
        encoding = S3.Config.Config().encoding

    if type(string) == unicode:
        return string

    if not silent:
        debug("Unicodising %r using %s" % (string, encoding))
    try:
        return unicode(string, encoding, errors)
    except UnicodeDecodeError:
        raise UnicodeDecodeError("Conversion to unicode failed: %r" % string)
__all__.append("unicodise")

def unicodise_s(string, encoding = None, errors = "replace"):
    """
    Alias to silent version of unicodise
    """
    return unicodise(string, encoding, errors, True)
__all__.append("unicodise_s")

def deunicodise(string, encoding = None, errors = "replace", silent=False):
    """
    Convert unicode 'string' to <type str>, by default replacing
    all invalid characters with '?' or raise an exception.
    """

    if not encoding:
        encoding = S3.Config.Config().encoding

    if type(string) != unicode:
        return string

    if not silent:
        debug("DeUnicodising %r using %s" % (string, encoding))
    try:
        return string.encode(encoding, errors)
    except UnicodeEncodeError:
        raise UnicodeEncodeError("Conversion from unicode failed: %r" % string)
__all__.append("deunicodise")

def deunicodise_s(string, encoding = None, errors = "replace"):
    """
    Alias to silent version of deunicodise
    """
    return deunicodise(string, encoding, errors, True)
__all__.append("deunicodise_s")

def unicodise_safe(string, encoding = None):
    """
    Convert 'string' to Unicode according to current encoding
    and replace all invalid characters with '?'
    """

    return unicodise(deunicodise(string, encoding), encoding).replace(u'\ufffd', '?')
__all__.append("unicodise_safe")

def decode_from_s3(string, errors = "replace"):
    """
    Convert S3 UTF-8 'string' to Unicode or raise an exception.
    """
    if type(string) == unicode:
        return string
    # Be quiet by default
    #debug("Decoding string from S3: %r" % string)
    try:
        return unicode(string, "UTF-8", errors)
    except UnicodeDecodeError:
        raise UnicodeDecodeError("Conversion to unicode failed: %r" % string)
__all__.append("decode_from_s3")

def encode_to_s3(string, errors = "replace"):
    """
    Convert Unicode to S3 UTF-8 'string', by default replacing
    all invalid characters with '?' or raise an exception.
    """
    if type(string) != unicode:
        return string
    # Be quiet by default
    #debug("Encoding string to S3: %r" % string)
    try:
        return string.encode("UTF-8", errors)
    except UnicodeEncodeError:
        raise UnicodeEncodeError("Conversion from unicode failed: %r" % string)
__all__.append("encode_to_s3")

## Low level methods
def urlencode_string(string, urlencoding_mode = None, unicode_output=False):
    string = encode_to_s3(string)

    if urlencoding_mode is None:
        urlencoding_mode = S3.Config.Config().urlencoding_mode

    if urlencoding_mode == "verbatim":
        ## Don't do any pre-processing
        return string

    encoded = quote(string, safe="~/")
    debug("String '%s' encoded to '%s'" % (string, encoded))
    if unicode_output:
        return decode_from_s3(encoded)
    else:
        return encode_to_s3(encoded)
__all__.append("urlencode_string")

def replace_nonprintables(string):
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
    if modified and S3.Config.Config().urlencoding_mode != "fixbucket":
        warning("%d non-printable characters replaced in: %s" % (modified, new_string))
    return new_string
__all__.append("replace_nonprintables")

def time_to_epoch(t):
    """Convert time specified in a variety of forms into UNIX epoch time.
    Accepts datetime.datetime, int, anything that has a strftime() method, and standard time 9-tuples
    """
    if isinstance(t, int):
        # Already an int
        return t
    elif isinstance(t, tuple) or isinstance(t, time.struct_time):
        # Assume it's a time 9-tuple
        return int(time.mktime(t))
    elif hasattr(t, 'timetuple'):
        # Looks like a datetime object or compatible
        return int(time.mktime(t.timetuple()))
    elif hasattr(t, 'strftime'):
        # Looks like the object supports standard srftime()
        return int(t.strftime('%s'))
    elif isinstance(t, str) or isinstance(t, unicode) or isinstance(t, bytes):
        # See if it's a string representation of an epoch
        try:
            # Support relative times (eg. "+60")
            if t.startswith('+'):
                return time.time() + int(t[1:])
            return int(t)
        except ValueError:
            # Try to parse it as a timestamp string
            try:
                return time.strptime(t)
            except ValueError as ex:
                # Will fall through
                debug("Failed to parse date with strptime: %s", ex)
                pass
    raise S3.Exceptions.ParameterError('Unable to convert %r to an epoch time. Pass an epoch time. Try `date -d \'now + 1 year\' +%%s` (shell) or time.mktime (Python).' % t)


def check_bucket_name(bucket, dns_strict = True):
    if dns_strict:
        invalid = re.search("([^a-z0-9\.-])", bucket, re.UNICODE)
        if invalid:
            raise S3.Exceptions.ParameterError("Bucket name '%s' contains disallowed character '%s'. The only supported ones are: lowercase us-ascii letters (a-z), digits (0-9), dot (.) and hyphen (-)." % (bucket, invalid.groups()[0]))
    else:
        invalid = re.search("([^A-Za-z0-9\._-])", bucket, re.UNICODE)
        if invalid:
            raise S3.Exceptions.ParameterError("Bucket name '%s' contains disallowed character '%s'. The only supported ones are: us-ascii letters (a-z, A-Z), digits (0-9), dot (.), hyphen (-) and underscore (_)." % (bucket, invalid.groups()[0]))

    if len(bucket) < 3:
        raise S3.Exceptions.ParameterError("Bucket name '%s' is too short (min 3 characters)" % bucket)
    if len(bucket) > 255:
        raise S3.Exceptions.ParameterError("Bucket name '%s' is too long (max 255 characters)" % bucket)
    if dns_strict:
        if len(bucket) > 63:
            raise S3.Exceptions.ParameterError("Bucket name '%s' is too long (max 63 characters)" % bucket)
        if re.search("-\.", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must not contain sequence '-.' for DNS compatibility" % bucket)
        if re.search("\.\.", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must not contain sequence '..' for DNS compatibility" % bucket)
        if not re.search("^[0-9a-z]", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must start with a letter or a digit" % bucket)
        if not re.search("[0-9a-z]$", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must end with a letter or a digit" % bucket)
    return True
__all__.append("check_bucket_name")

def check_bucket_name_dns_conformity(bucket):
    try:
        return check_bucket_name(bucket, dns_strict = True)
    except S3.Exceptions.ParameterError:
        return False
__all__.append("check_bucket_name_dns_conformity")

def check_bucket_name_dns_support(bucket_host, bucket_name):
    """
    Check whether either the host_bucket support buckets and
    either bucket name is dns compatible
    """
    if "%(bucket)s" not in bucket_host:
        return False

    return check_bucket_name_dns_conformity(bucket_name)
__all__.append("check_bucket_name_dns_support")

def getBucketFromHostname(hostname):
    """
    bucket, success = getBucketFromHostname(hostname)

    Only works for hostnames derived from bucket names
    using Config.host_bucket pattern.

    Returns bucket name and a boolean success flag.
    """
    if "%(bucket)s" not in S3.Config.Config().host_bucket:
        return (hostname, False)

    # Create RE pattern from Config.host_bucket
    pattern = S3.Config.Config().host_bucket % { 'bucket' : '(?P<bucket>.*)' }
    m = re.match(pattern, hostname, re.UNICODE)
    if not m:
        return (hostname, False)
    return m.group(1), True
__all__.append("getBucketFromHostname")

def getHostnameFromBucket(bucket):
    return S3.Config.Config().host_bucket % { 'bucket' : bucket }
__all__.append("getHostnameFromBucket")


def calculateChecksum(buffer, mfile, offset, chunk_size, send_chunk):
    md5_hash = md5()
    size_left = chunk_size
    if buffer == '':
        mfile.seek(offset)
        while size_left > 0:
            data = mfile.read(min(send_chunk, size_left))
            md5_hash.update(data)
            size_left -= len(data)
    else:
        md5_hash.update(buffer)

    return md5_hash.hexdigest()


__all__.append("calculateChecksum")


# Deal with the fact that pwd and grp modules don't exist for Windows
try:
    import pwd
    def getpwuid_username(uid):
        """returns a username from the password databse for the given uid"""
        return unicodise_s(pwd.getpwuid(uid).pw_name)
except ImportError:
    import getpass
    def getpwuid_username(uid):
        return unicodise_s(getpass.getuser())
__all__.append("getpwuid_username")

try:
    import grp
    def getgrgid_grpname(gid):
        """returns a groupname from the group databse for the given gid"""
        return unicodise_s(grp.getgrgid(gid).gr_name)
except ImportError:
    def getgrgid_grpname(gid):
        return u"nobody"

__all__.append("getgrgid_grpname")



# vim:et:ts=4:sts=4:ai

