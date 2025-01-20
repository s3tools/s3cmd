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

from __future__ import absolute_import

import logging
import datetime
import locale
import re
import os
import io
import sys
import json
import time

from logging import debug, warning

from .ExitCodes import EX_OSFILE

try:
    import dateutil.parser
    import dateutil.tz
except ImportError:
    sys.stderr.write(u"""
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
ImportError trying to import dateutil.parser and dateutil.tz.
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
    # python 3 support
    import httplib
except ImportError:
    import http.client as httplib

try:
    from configparser import (NoOptionError, NoSectionError,
                              MissingSectionHeaderError, ParsingError,
                              ConfigParser as PyConfigParser)
except ImportError:
    # Python2 fallback code
    from ConfigParser import (NoOptionError, NoSectionError,
                              MissingSectionHeaderError, ParsingError,
                              ConfigParser as PyConfigParser)

from . import Progress
from .SortedDict import SortedDict
from .BaseUtils import (s3_quote, getTreeFromXml, getDictFromTree,
                        base_unicodise, dateRFC822toPython)


try:
    unicode
except NameError:
    # python 3 support
    # In python 3, unicode -> str, and str -> bytes
    unicode = str

PY3 = (sys.version_info >= (3, 0))


def is_bool_true(value):
    """Check to see if a string is true, yes, on, or 1

    value may be a str, or unicode.

    Return True if it is
    """
    if type(value) == unicode:
        return value.lower() in ["true", "yes", "on", "1"]
    elif type(value) == bool and value == True:
        return True
    else:
        return False


def is_bool_false(value):
    """Check to see if a string is false, no, off, or 0

    value may be a str, or unicode.

    Return True if it is
    """
    if type(value) == unicode:
        return value.lower() in ["false", "no", "off", "0"]
    elif type(value) == bool and value == False:
        return True
    else:
        return False


def is_bool(value):
    """Check a string value to see if it is bool"""
    return is_bool_true(value) or is_bool_false(value)


class Config(object):
    _instance = None
    _parsed_files = []
    _doc = {}
    access_key = u""
    secret_key = u""
    access_token = u""
    _access_token_refresh = True
    _access_token_expiration = None
    _access_token_last_update = None
    host_base = u"s3.amazonaws.com"
    host_bucket = u"%(bucket)s.s3.amazonaws.com"
    sts_endpoint = u"sts.amazonaws.com"
    kms_key = u""    #can't set this and Server Side Encryption at the same time
    # simpledb_host looks useless, legacy? to remove?
    simpledb_host = u"sdb.amazonaws.com"
    cloudfront_host = u"cloudfront.amazonaws.com"
    verbosity = logging.WARNING
    progress_meter = sys.stdout.isatty()
    progress_class = Progress.ProgressCR
    send_chunk = 64 * 1024
    recv_chunk = 64 * 1024
    list_md5 = False
    long_listing = False
    human_readable_sizes = False
    extra_headers = SortedDict(ignore_case = True)
    force = False
    server_side_encryption = False
    enable = None
    get_continue = False
    put_continue = False
    upload_id = u""
    skip_existing = False
    recursive = False
    restore_days = 1
    restore_priority = u"Standard"
    acl_public = None
    acl_grants = []
    acl_revokes = []
    proxy_host = u""
    proxy_port = 3128
    encrypt = False
    dry_run = False
    add_encoding_exts = u""
    preserve_attrs = True
    preserve_attrs_list = [
        u'uname',    # Verbose owner Name (e.g. 'root')
        u'uid',      # Numeric user ID (e.g. 0)
        u'gname',    # Group name (e.g. 'users')
        u'gid',      # Numeric group ID (e.g. 100)
        u'atime',    # Last access timestamp
        u'mtime',    # Modification timestamp
        u'ctime',    # Creation timestamp
        u'mode',     # File mode (e.g. rwxr-xr-x = 755)
        u'md5',      # File MD5 (if known)
        #u'acl',     # Full ACL (not yet supported)
    ]
    keep_dirs = False
    delete_removed = False
    delete_after = False
    delete_after_fetch = False
    max_delete = -1
    limit = -1
    _doc['delete_removed'] = u"[sync] Remove remote S3 objects when local file has been deleted"
    delay_updates = False  # OBSOLETE
    gpg_passphrase = u""
    gpg_command = u""
    gpg_encrypt = u"%(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
    gpg_decrypt = u"%(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
    use_https = True
    ca_certs_file = u""
    ssl_client_key_file = u""
    ssl_client_cert_file = u""
    check_ssl_certificate = True
    check_ssl_hostname = True
    bucket_location = u"US"
    default_mime_type = u"binary/octet-stream"
    guess_mime_type = True
    use_mime_magic = True
    mime_type = u""
    enable_multipart = True
    # Chunk size is at the same time the chunk size and the threshold
    multipart_chunk_size_mb = 15    # MiB
    # Maximum chunk size for s3-to-s3 copy is 5 GiB.
    # But, use a lot lower value by default (1GiB)
    multipart_copy_chunk_size_mb = 1 * 1024
    # Maximum chunks on AWS S3, could be different on other S3-compatible APIs
    multipart_max_chunks = 10000
    # List of checks to be performed for 'sync'
    sync_checks = ['size', 'md5']   # 'weak-timestamp'
    # List of compiled REGEXPs
    exclude = []
    include = []
    # Dict mapping compiled REGEXPs back to their textual form
    debug_exclude = {}
    debug_include = {}
    encoding = locale.getpreferredencoding() or "UTF-8"
    urlencoding_mode = u"normal"
    log_target_prefix = u""
    reduced_redundancy = False
    storage_class = u""
    follow_symlinks = False
    # If too big, this value can be overridden by the OS socket timeouts max values.
    # For example, on Linux, a connection attempt will automatically timeout after 120s.
    socket_timeout = 300
    invalidate_on_cf = False
    # joseprio: new flags for default index invalidation
    invalidate_default_index_on_cf = False
    invalidate_default_index_root_on_cf = True
    website_index = u"index.html"
    website_error = u""
    website_endpoint = u"http://%(bucket)s.s3-website-%(location)s.amazonaws.com/"
    additional_destinations = []
    files_from = []
    cache_file = u""
    add_headers = u""
    remove_headers = []
    expiry_days = u""
    expiry_date = u""
    expiry_prefix = u""
    skip_destination_validation = False
    signature_v2 = False
    limitrate = 0
    requester_pays = False
    stop_on_error = False
    content_disposition = u""
    content_type = u""
    stats = False
    # Disabled by default because can create a latency with a CONTINUE status reply
    # expected for every send file requests.
    use_http_expect = False
    signurl_use_https = False
    # Maximum sleep duration for throttle / limitrate.
    # s3 will timeout if a request/transfer is stuck for more than a short time
    throttle_max = 100
    public_url_use_https = False
    connection_pooling = True
    # How long in seconds a connection can be kept idle in the pool and still
    # be alive. AWS s3 is supposed to close connections that are idle for 20
    # seconds or more, but in real life, undocumented, it closes https conns
    # after around 6s of inactivity.
    connection_max_age = 5
    # Not an AWS standard
    # allow the listing results to be returned in unsorted order.
    # This may be faster when listing very large buckets.
    list_allow_unordered = False
    # Maximum attempts of re-issuing failed requests
    max_retries = 5

    ## Creating a singleton
    def __new__(self, configfile = None, access_key=None, secret_key=None, access_token=None):
        if self._instance is None:
            self._instance = object.__new__(self)
        return self._instance

    def __init__(self, configfile = None, access_key=None, secret_key=None, access_token=None):
        if configfile:
            try:
                self.read_config_file(configfile)
            except IOError:
                if 'AWS_SHARED_CREDENTIALS_FILE' in os.environ or 'AWS_CREDENTIAL_FILE' in os.environ or 'AWS_PROFILE' in os.environ:
                    self.aws_credential_file()

            # override these if passed on the command-line
            # Allow blank secret_key
            if access_key and secret_key is not None:
                self.access_key = access_key
                self.secret_key = secret_key
            if access_token:
                self.access_token = access_token
                # Do not refresh the IAM role when an access token is provided.
                self._access_token_refresh = False

            if len(self.access_key) == 0:
                env_access_key = os.getenv('AWS_ACCESS_KEY') or os.getenv('AWS_ACCESS_KEY_ID')
                env_secret_key = os.getenv('AWS_SECRET_KEY') or os.getenv('AWS_SECRET_ACCESS_KEY')
                env_access_token = os.getenv('AWS_SESSION_TOKEN') or os.getenv('AWS_SECURITY_TOKEN')
                if env_access_key:
                    if not env_secret_key:
                        raise ValueError(
                            "AWS_ACCESS_KEY environment variable is used but"
                            " AWS_SECRET_KEY variable is missing"
                        )
                    # py3 getenv returns unicode and py2 returns bytes.
                    self.access_key = base_unicodise(env_access_key)
                    self.secret_key = base_unicodise(env_secret_key)
                    if env_access_token:
                        # Do not refresh the IAM role when an access token is provided.
                        self._access_token_refresh = False
                        self.access_token = base_unicodise(env_access_token)
                else:
                    self.role_config()

            #TODO check KMS key is valid
            if self.kms_key and self.server_side_encryption == True:
                warning('Cannot have server_side_encryption (S3 SSE) and KMS_key set (S3 KMS). KMS encryption will be used. Please set server_side_encryption to False')
            if self.kms_key and self.signature_v2 == True:
                raise Exception('KMS encryption requires signature v4. Please set signature_v2 to False')

    def role_config(self):
        """
        Get credentials from IAM authentication and STS AssumeRole
        """
        try:
            sts_endpoint = self.sts_endpoint
            role_arn = os.environ.get('AWS_ROLE_ARN')
            if role_arn:
                role_session_name = 'role-session-%s' % (int(time.time()))
                params = {
                    'Action': 'AssumeRole',
                    'Version': '2011-06-15',
                    'RoleArn': role_arn,
                    'RoleSessionName': role_session_name,
                }
                web_identity_token_file = os.environ.get('AWS_WEB_IDENTITY_TOKEN_FILE')
                if web_identity_token_file:
                    with open(web_identity_token_file) as f:
                        web_identity_token = f.read().rstrip()
                    params['Action'] = 'AssumeRoleWithWebIdentity'
                    params['WebIdentityToken'] = web_identity_token
                encoded_params = '&'.join([
                    '%s=%s' % (k, s3_quote(v, unicode_output=True))
                    for k, v in params.items()
                ])
                sts_endpoint = os.environ.get("AWS_STS_ENDPOINT", sts_endpoint) 
                if os.environ.get("AWS_STS_REGIONAL_ENDPOINTS") == "regional":
                    # Check if the AWS_REGION variable is available to use as a region.
                    region = os.environ.get("AWS_REGION")
                    if not region:
                        # Otherwise use the bucket location
                        region = self.bucket_location
                    sts_endpoint = "sts.%s.amazonaws.com" % region
                conn = httplib.HTTPSConnection(host=sts_endpoint,
                                               timeout=2)
                conn.request('POST', '/?' + encoded_params)
                resp = conn.getresponse()
                resp_content = resp.read()
                if resp.status == 200 and len(resp_content) > 1:
                    tree = getTreeFromXml(resp_content)
                    result_dict = getDictFromTree(tree)
                    if tree.tag == "AssumeRoleResponse":
                        creds = result_dict['AssumeRoleResult']['Credentials']
                    elif tree.tag == "AssumeRoleWithWebIdentityResponse":
                        creds = result_dict['AssumeRoleWithWebIdentityResult']['Credentials']
                    else:
                        raise IOError("Unexpected XML message from STS server: <%s />" % tree.tag)
                    Config().update_option('access_key', creds['AccessKeyId'])
                    Config().update_option('secret_key', creds['SecretAccessKey'])
                    Config().update_option('access_token', creds['SessionToken'])
                    expiration = dateRFC822toPython(base_unicodise(creds['Expiration']))
                    # Add a timedelta to prevent any expiration if the EC2 machine is not at the right date
                    self._access_token_expiration = expiration - datetime.timedelta(minutes=15)
                    # last update date is not provided in STS responses
                    self._access_token_last_update = datetime.datetime.now(dateutil.tz.tzutc())
                    # Others variables : Code / Type
                else:
                    raise IOError
            else:
                conn = httplib.HTTPConnection(host='169.254.169.254',
                                              timeout=2)

                # To use Instance Metadata Service (IMDSv2), we first need to obtain a token, then
                # supply it with every IMDS HTTP call. More info:
                #
                #   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
                #
                # 60 seconds is arbitrary, but since we're just pulling small bits of data from the
                # local instance, it should be plenty of time.
                #
                # There's a chance that there are "mostly AWS compatible" systems that might offer
                # only IMDSv1 emulation, so we make this optional -- if we can't get the token, we
                # just proceed without.
                #
                # More discussion at https://github.com/Hyperbase/hyperbase/pull/22259
                #
                imds_auth = {}
                try:
                    imds_ttl = {"X-aws-ec2-metadata-token-ttl-seconds": "60"}
                    conn.request('PUT', "/latest/api/token", headers=imds_ttl)
                    resp = conn.getresponse()
                    resp_content = resp.read()
                    if resp.status == 200:
                        imds_token = base_unicodise(resp_content)
                        imds_auth = {"X-aws-ec2-metadata-token": imds_token}
                except Exception:
                    # Ensure to close the connection in case of timeout or
                    # anything. This will avoid CannotSendRequest errors for
                    # the next request.
                    conn.close()

                conn.request('GET', "/latest/meta-data/iam/security-credentials/", headers=imds_auth)
                resp = conn.getresponse()
                files = resp.read()
                if resp.status == 200 and len(files) > 1:
                    conn.request('GET',
                                 "/latest/meta-data/iam/security-credentials/%s" % files.decode('utf-8'),
                                 headers=imds_auth)
                    resp=conn.getresponse()
                    if resp.status == 200:
                        resp_content = base_unicodise(resp.read())
                        creds = json.loads(resp_content)
                        Config().update_option('access_key', base_unicodise(creds['AccessKeyId']))
                        Config().update_option('secret_key', base_unicodise(creds['SecretAccessKey']))
                        Config().update_option('access_token', base_unicodise(creds['Token']))
                        expiration = dateRFC822toPython(base_unicodise(creds['Expiration']))
                        # Add a timedelta to prevent any expiration if the EC2 machine is not at the right date
                        self._access_token_expiration = expiration - datetime.timedelta(minutes=15)
                        self._access_token_last_update = dateRFC822toPython(base_unicodise(creds['LastUpdated']))
                        # Others variables : Code / Type
                    else:
                        raise IOError
                else:
                    raise IOError
        except Exception:
            raise

    def role_refresh(self):
        if self._access_token_refresh:
            now = datetime.datetime.now(dateutil.tz.tzutc())
            if self._access_token_expiration \
               and now < self._access_token_expiration \
               and self._access_token_last_update \
               and self._access_token_last_update <= now:
                # current token is still valid. No need to refresh it
                return
            try:
                self.role_config()
            except Exception:
                warning("Could not refresh role")

    def aws_credential_file(self):
        try:
            aws_credential_file = os.path.expanduser('~/.aws/credentials')
            credential_file_from_env = os.environ.get('AWS_SHARED_CREDENTIALS_FILE') \
                or os.environ.get('AWS_CREDENTIAL_FILE')
            if credential_file_from_env and \
               os.path.isfile(credential_file_from_env):
                aws_credential_file = base_unicodise(credential_file_from_env)
            elif not os.path.isfile(aws_credential_file):
                return

            config = PyConfigParser()

            debug("Reading AWS credentials from %s" % (aws_credential_file))
            with io.open(aws_credential_file, "r",
                         encoding=getattr(self, 'encoding', 'UTF-8')) as fp:
                config_string = fp.read()
            try:
                try:
                    buf = io.StringIO(config_string)
                    if PY3:
                      config.read_file(buf)
                    else:
                      config.readfp(buf)
                except MissingSectionHeaderError:
                    # if header is missing, this could be deprecated
                    # credentials file format as described here:
                    # https://blog.csanchez.org/2011/05/
                    # then do the hacky-hack and add default header
                    # to be able to read the file with PyConfigParser()
                    config_string = u'[default]\n' + config_string
                    buf = io.StringIO(config_string)
                    if PY3:
                      config.read_file(buf)
                    else:
                      config.readfp(buf)
            except ParsingError as exc:
                raise ValueError(
                    "Error reading aws_credential_file "
                    "(%s): %s" % (aws_credential_file, str(exc)))

            profile = base_unicodise(os.environ.get('AWS_PROFILE', "default"))
            debug("Using AWS profile '%s'" % (profile))

            # get_key - helper function to read the aws profile credentials
            # including the legacy ones as described here:
            # https://blog.csanchez.org/2011/05/
            def get_key(profile, key, legacy_key, print_warning=True):
                result = None

                try:
                    result = config.get(profile, key)
                except NoOptionError as e:
                    # we may want to skip warning message for optional keys
                    if print_warning:
                        warning("Couldn't find key '%s' for the AWS Profile "
                                "'%s' in the credentials file '%s'",
                                e.option, e.section, aws_credential_file)
                    # if the legacy_key defined and original one wasn't found,
                    # try read the legacy_key
                    if legacy_key:
                        try:
                            key = legacy_key
                            profile = "default"
                            result = config.get(profile, key)
                            warning(
                                "Legacy configuration key '%s' used, please use"
                                " the standardized config format as described "
                                "here: https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/",
                                key)
                        except NoOptionError as e:
                            pass

                if result:
                    debug("Found the configuration option '%s' for the AWS "
                          "Profile '%s' in the credentials file %s",
                          key, profile, aws_credential_file)
                return result

            profile_access_key = get_key(profile, "aws_access_key_id",
                                         "AWSAccessKeyId")
            if profile_access_key:
                Config().update_option('access_key',
                                       base_unicodise(profile_access_key))

            profile_secret_key = get_key(profile, "aws_secret_access_key",
                                         "AWSSecretKey")
            if profile_secret_key:
                Config().update_option('secret_key',
                                       base_unicodise(profile_secret_key))

            profile_access_token = get_key(profile, "aws_session_token", None,
                                           False)
            if profile_access_token:
                Config().update_option('access_token',
                                       base_unicodise(profile_access_token))

        except IOError as e:
            warning("Errno %d accessing credentials file %s", e.errno,
                    aws_credential_file)
        except NoSectionError as e:
            warning("Couldn't find AWS Profile '%s' in the credentials file "
                    "'%s'", profile, aws_credential_file)

    def option_list(self):
        retval = []
        for option in dir(self):
            ## Skip attributes that start with underscore or are not string, int or bool
            option_type = type(getattr(Config, option))
            if option.startswith("_") or \
               not (option_type in (
                    type(u"string"), # str
                        type(42),   # int
                    type(True))):   # bool
                continue
            retval.append(option)
        return retval

    def read_config_file(self, configfile):
        cp = ConfigParser(configfile)
        for option in self.option_list():
            _option = cp.get(option)
            if _option is not None:
                _option = _option.strip()
            self.update_option(option, _option)

        # allow acl_public to be set from the config file too, even though by
        # default it is set to None, and not present in the config file.
        if cp.get('acl_public'):
            self.update_option('acl_public', cp.get('acl_public'))

        if cp.get('add_headers'):
            for option in cp.get('add_headers').split(","):
                (key, value) = option.split(':', 1)
                self.extra_headers[key.strip()] = value.strip()

        self._parsed_files.append(configfile)

    def dump_config(self, stream):
        ConfigDumper(stream).dump(u"default", self)

    def update_option(self, option, value):
        if value is None:
            return

        #### Handle environment reference
        if unicode(value).startswith("$"):
            return self.update_option(option, os.getenv(value[1:]))

        #### Special treatment of some options
        ## verbosity must be known to "logging" module
        if option == "verbosity":
            # support integer verboisities
            try:
                value = int(value)
            except ValueError:
                try:
                    # otherwise it must be a key known to the logging module
                    try:
                        # python 3 support
                        value = logging._levelNames[value]
                    except AttributeError:
                        value = logging._nameToLevel[value]
                except KeyError:
                    raise ValueError("Config: verbosity level '%s' is not valid" % value)

        elif option == "limitrate":
            #convert kb,mb to bytes
            if value.endswith("k") or value.endswith("K"):
                shift = 10
            elif value.endswith("m") or value.endswith("M"):
                shift = 20
            else:
                shift = 0
            try:
                value = shift and int(value[:-1]) << shift or int(value)
            except Exception:
                raise ValueError("Config: value of option %s must have suffix m, k, or nothing, not '%s'" % (option, value))

        ## allow yes/no, true/false, on/off and 1/0 for boolean options
        ## Some options default to None, if that's the case check the value to see if it is bool
        elif (type(getattr(Config, option)) is type(True) or              # Config is bool
              (getattr(Config, option) is None and is_bool(value))):  # Config is None and value is bool
            if is_bool_true(value):
                value = True
            elif is_bool_false(value):
                value = False
            else:
                raise ValueError("Config: value of option '%s' must be Yes or No, not '%s'" % (option, value))

        elif type(getattr(Config, option)) is type(42):     # int
            try:
                value = int(value)
            except ValueError:
                raise ValueError("Config: value of option '%s' must be an integer, not '%s'" % (option, value))

        elif option in ["host_base", "host_bucket", "cloudfront_host"]:
            if value.startswith("http://"):
                value = value[7:]
            elif value.startswith("https://"):
                value = value[8:]


        setattr(Config, option, value)

class ConfigParser(object):
    def __init__(self, file, sections = []):
        self.cfg = {}
        self.parse_file(file, sections)

    def parse_file(self, file, sections = []):
        debug("ConfigParser: Reading file '%s'" % file)
        if type(sections) != type([]):
            sections = [sections]
        in_our_section = True
        r_comment = re.compile(r'^\s*#.*')
        r_empty = re.compile(r'^\s*$')
        r_section = re.compile(r'^\[([^\]]+)\]')
        r_data = re.compile(r'^\s*(?P<key>\w+)\s*=\s*(?P<value>.*)')
        r_quotes = re.compile(r'^"(.*)"\s*$')
        with io.open(file, "r", encoding=self.get('encoding', 'UTF-8')) as fp:
            for line in fp:
                if r_comment.match(line) or r_empty.match(line):
                    continue
                is_section = r_section.match(line)
                if is_section:
                    section = is_section.groups()[0]
                    in_our_section = (section in sections) or (len(sections) == 0)
                    continue
                is_data = r_data.match(line)
                if is_data and in_our_section:
                    data = is_data.groupdict()
                    if r_quotes.match(data["value"]):
                        data["value"] = data["value"][1:-1]
                    self.__setitem__(data["key"], data["value"])
                    if data["key"] in ("access_key", "secret_key", "gpg_passphrase"):
                        print_value = ("%s...%d_chars...%s") % (data["value"][:2], len(data["value"]) - 3, data["value"][-1:])
                    else:
                        print_value = data["value"]
                    debug("ConfigParser: %s->%s" % (data["key"], print_value))
                    continue
                warning("Ignoring invalid line in '%s': %s" % (file, line))

    def __getitem__(self, name):
        return self.cfg[name]

    def __setitem__(self, name, value):
        self.cfg[name] = value

    def get(self, name, default = None):
        if name in self.cfg:
            return self.cfg[name]
        return default

class ConfigDumper(object):
    def __init__(self, stream):
        self.stream = stream

    def dump(self, section, config):
        self.stream.write(u"[%s]\n" % section)
        for option in config.option_list():
            value = getattr(config, option)
            if option == "verbosity":
                # we turn level numbers back into strings if possible
                if isinstance(value, int):
                    try:
                        try:
                            # python 3 support
                            value = logging._levelNames[value]
                        except AttributeError:
                            value = logging._levelToName[value]
                    except KeyError:
                        pass
            self.stream.write(u"%s = %s\n" % (option, value))

# vim:et:ts=4:sts=4:ai
