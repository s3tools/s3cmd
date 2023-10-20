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

import os
import time
import re
import string as string_mod
import random
import errno
from logging import debug


try:
    unicode
except NameError:
    # python 3 support
    # In python 3, unicode -> str, and str -> bytes
    unicode = str


import S3.Config
import S3.Exceptions

from S3.BaseUtils import (base_urlencode_string, base_replace_nonprintables,
                          base_unicodise, base_deunicodise, md5)


__all__ = []


def formatSize(size, human_readable=False, floating_point=False):
    size = floating_point and float(size) or int(size)
    if human_readable:
        coeffs = ['K', 'M', 'G', 'T']
        coeff = ""
        while size > 2048:
            size /= 1024
            coeff = coeffs.pop(0)
        return (floating_point and float(size) or int(size), coeff)
    else:
        return (size, "")
__all__.append("formatSize")


def convertHeaderTupleListToDict(list):
    """
    Header keys are always in lowercase in python2 but not in python3.
    """
    retval = {}
    for tuple in list:
        retval[tuple[0].lower()] = tuple[1]
    return retval
__all__.append("convertHeaderTupleListToDict")

_rnd_chars = string_mod.ascii_letters + string_mod.digits
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

def unicodise(string, encoding=None, errors='replace', silent=False):
    if not encoding:
        encoding = S3.Config.Config().encoding
    return base_unicodise(string, encoding, errors, silent)
__all__.append("unicodise")


def unicodise_s(string, encoding=None, errors='replace'):
    """
    Alias to silent version of unicodise
    """
    return unicodise(string, encoding, errors, True)
__all__.append("unicodise_s")


def deunicodise(string, encoding=None, errors='replace', silent=False):
    if not encoding:
        encoding = S3.Config.Config().encoding
    return base_deunicodise(string, encoding, errors, silent)
__all__.append("deunicodise")


def deunicodise_s(string, encoding=None, errors='replace'):
    """
    Alias to silent version of deunicodise
    """
    return deunicodise(string, encoding, errors, True)
__all__.append("deunicodise_s")


def unicodise_safe(string, encoding=None):
    """
    Convert 'string' to Unicode according to current encoding
    and replace all invalid characters with '?'
    """

    return unicodise(deunicodise(string, encoding), encoding).replace(u'\ufffd', '?')
__all__.append("unicodise_safe")


## Low level methods
def urlencode_string(string, urlencoding_mode=None, unicode_output=False):
    if urlencoding_mode is None:
        urlencoding_mode = S3.Config.Config().urlencoding_mode
    return base_urlencode_string(string, urlencoding_mode, unicode_output)
__all__.append("urlencode_string")


def replace_nonprintables(string):
    """
    replace_nonprintables(string)

    Replaces all non-printable characters 'ch' in 'string'
    where ord(ch) <= 26 with ^@, ^A, ... ^Z
    """
    warning_message = (S3.Config.Config().urlencoding_mode != "fixbucket")
    return base_replace_nonprintables(string, warning_message)
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


def check_bucket_name(bucket, dns_strict=True):
    if dns_strict:
        invalid = re.search(r"([^a-z0-9\.-])", bucket, re.UNICODE)
        if invalid:
            raise S3.Exceptions.ParameterError("Bucket name '%s' contains disallowed character '%s'. The only supported ones are: lowercase us-ascii letters (a-z), digits (0-9), dot (.) and hyphen (-)." % (bucket, invalid.groups()[0]))
    else:
        invalid = re.search(r"([^A-Za-z0-9\._-])", bucket, re.UNICODE)
        if invalid:
            raise S3.Exceptions.ParameterError("Bucket name '%s' contains disallowed character '%s'. The only supported ones are: us-ascii letters (a-z, A-Z), digits (0-9), dot (.), hyphen (-) and underscore (_)." % (bucket, invalid.groups()[0]))

    if len(bucket) < 3:
        raise S3.Exceptions.ParameterError("Bucket name '%s' is too short (min 3 characters)" % bucket)
    if len(bucket) > 255:
        raise S3.Exceptions.ParameterError("Bucket name '%s' is too long (max 255 characters)" % bucket)
    if dns_strict:
        if len(bucket) > 63:
            raise S3.Exceptions.ParameterError("Bucket name '%s' is too long (max 63 characters)" % bucket)
        if re.search(r"-\.", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must not contain sequence '-.' for DNS compatibility" % bucket)
        if re.search(r"\.\.", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must not contain sequence '..' for DNS compatibility" % bucket)
        if not re.search(r"^[0-9a-z]", bucket, re.UNICODE):
            raise S3.Exceptions.ParameterError("Bucket name '%s' must start with a letter or a digit" % bucket)
        if not re.search(r"[0-9a-z]$", bucket, re.UNICODE):
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
    pattern = S3.Config.Config().host_bucket.lower() % { 'bucket' : '(?P<bucket>.*)' }
    m = re.match(pattern, hostname, re.UNICODE)
    if not m:
        return (hostname, False)
    return m.group(1), True
__all__.append("getBucketFromHostname")


def getHostnameFromBucket(bucket):
    return S3.Config.Config().host_bucket.lower() % { 'bucket' : bucket }
__all__.append("getHostnameFromBucket")


# Deal with the fact that pwd and grp modules don't exist for Windows
try:
    import pwd
    def getpwuid_username(uid):
        """returns a username from the password database for the given uid"""
        return unicodise_s(pwd.getpwuid(uid).pw_name)
except ImportError:
    import getpass
    def getpwuid_username(uid):
        return unicodise_s(getpass.getuser())
__all__.append("getpwuid_username")

try:
    import grp
    def getgrgid_grpname(gid):
        """returns a groupname from the group database for the given gid"""
        return unicodise_s(grp.getgrgid(gid).gr_name)
except ImportError:
    def getgrgid_grpname(gid):
        return u"nobody"

__all__.append("getgrgid_grpname")



# vim:et:ts=4:sts=4:ai
