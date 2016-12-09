# -*- coding: utf-8 -*-

## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2
## Copyright: TGRMN Software and contributors

from __future__ import absolute_import

import logging
from logging import debug, warning, error
import re
import os
import sys
from . import Progress
from .SortedDict import SortedDict
try:
    # python 3 support
    import httplib
except ImportError:
    import http.client as httplib
import locale
try:
    import json
except ImportError:
    pass

class Config(object):
    _instance = None
    _parsed_files = []
    _doc = {}
    access_key = ""
    secret_key = ""
    access_token = ""
    _access_token_refresh = True
    host_base = "s3.amazonaws.com"
    host_bucket = "%(bucket)s.s3.amazonaws.com"
    kms_key = ""    #can't set this and Server Side Encryption at the same time
    # simpledb_host looks useless, legacy? to remove?
    simpledb_host = "sdb.amazonaws.com"
    cloudfront_host = "cloudfront.amazonaws.com"
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
    upload_id = None
    skip_existing = False
    recursive = False
    restore_days = 1
    restore_priority = "Standard"
    acl_public = None
    acl_grants = []
    acl_revokes = []
    proxy_host = ""
    proxy_port = 3128
    encrypt = False
    dry_run = False
    add_encoding_exts = ""
    preserve_attrs = True
    preserve_attrs_list = [
        'uname',    # Verbose owner Name (e.g. 'root')
        'uid',      # Numeric user ID (e.g. 0)
        'gname',    # Group name (e.g. 'users')
        'gid',      # Numeric group ID (e.g. 100)
        'atime',    # Last access timestamp
        'mtime',    # Modification timestamp
        'ctime',    # Creation timestamp
        'mode',     # File mode (e.g. rwxr-xr-x = 755)
        'md5',      # File MD5 (if known)
        #'acl',     # Full ACL (not yet supported)
    ]
    delete_removed = False
    delete_after = False
    delete_after_fetch = False
    max_delete = -1
    limit = -1
    _doc['delete_removed'] = "[sync] Remove remote S3 objects when local file has been deleted"
    delay_updates = False  # OBSOLETE
    gpg_passphrase = ""
    gpg_command = ""
    gpg_encrypt = "%(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
    gpg_decrypt = "%(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s"
    use_https = True
    ca_certs_file = ""
    check_ssl_certificate = True
    check_ssl_hostname = True
    bucket_location = "US"
    default_mime_type = "binary/octet-stream"
    guess_mime_type = True
    use_mime_magic = True
    mime_type = ""
    enable_multipart = True
    multipart_chunk_size_mb = 15    # MB
    multipart_max_chunks = 10000    # Maximum chunks on AWS S3, could be different on other S3-compatible APIs
    # List of checks to be performed for 'sync'
    sync_checks = ['size', 'md5']   # 'weak-timestamp'
    # List of compiled REGEXPs
    exclude = []
    include = []
    # Dict mapping compiled REGEXPs back to their textual form
    debug_exclude = {}
    debug_include = {}
    encoding = locale.getpreferredencoding() or "UTF-8"
    urlencoding_mode = "normal"
    log_target_prefix = ""
    reduced_redundancy = False
    storage_class = ""
    follow_symlinks = False
    socket_timeout = 300
    invalidate_on_cf = False
    # joseprio: new flags for default index invalidation
    invalidate_default_index_on_cf = False
    invalidate_default_index_root_on_cf = True
    website_index = "index.html"
    website_error = ""
    website_endpoint = "http://%(bucket)s.s3-website-%(location)s.amazonaws.com/"
    additional_destinations = []
    files_from = []
    cache_file = ""
    add_headers = ""
    remove_headers = []
    expiry_days = ""
    expiry_date = ""
    expiry_prefix = ""
    signature_v2 = False
    limitrate = 0
    requester_pays = False
    stop_on_error = False
    content_disposition = None
    content_type = None
    stats = False
    # Disabled by default because can create a latency with a CONTINUE status reply
    # expected for every send file requests.
    use_http_expect = False

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
                if 'AWS_CREDENTIAL_FILE' in os.environ:
                    self.env_config()

            # override these if passed on the command-line
            if access_key and secret_key:
                self.access_key = access_key
                self.secret_key = secret_key
                
            if access_token:
                self.access_token = access_token
                # Do not refresh the IAM role when an access token is provided.
                self._access_token_refresh = False

            if len(self.access_key)==0:
                env_access_key = os.environ.get("AWS_ACCESS_KEY", None) or os.environ.get("AWS_ACCESS_KEY_ID", None)
                env_secret_key = os.environ.get("AWS_SECRET_KEY", None) or os.environ.get("AWS_SECRET_ACCESS_KEY", None)
                env_access_token = os.environ.get("AWS_SESSION_TOKEN", None) or os.environ.get("AWS_SECURITY_TOKEN", None)
                if env_access_key:
                    self.access_key = env_access_key
                    self.secret_key = env_secret_key
                    if env_access_token:
                        # Do not refresh the IAM role when an access token is provided.
                        self._access_token_refresh = False
                        self.access_token = env_access_token
                else:
                    self.role_config()

            #TODO check KMS key is valid
            if self.kms_key and self.server_side_encryption == True:
                warning('Cannot have server_side_encryption (S3 SSE) and KMS_key set (S3 KMS). KMS encryption will be used. Please set server_side_encryption to False')
            if self.kms_key and self.signature_v2 == True:
                raise Exception('KMS encryption requires signature v4. Please set signature_v2 to False')

    def role_config(self):
        if sys.version_info[0] * 10 + sys.version_info[1] < 26:
            error("IAM authentication requires Python 2.6 or newer")
            raise
        if not 'json' in sys.modules:
            error("IAM authentication not available -- missing module json")
            raise
        try:
            conn = httplib.HTTPConnection(host='169.254.169.254', timeout = 2)
            conn.request('GET', "/latest/meta-data/iam/security-credentials/")
            resp = conn.getresponse()
            files = resp.read()
            if resp.status == 200 and len(files)>1:
                conn.request('GET', "/latest/meta-data/iam/security-credentials/%s"%files)
                resp=conn.getresponse()
                if resp.status == 200:
                    creds=json.load(resp)
                    Config().update_option('access_key', creds['AccessKeyId'].encode('ascii'))
                    Config().update_option('secret_key', creds['SecretAccessKey'].encode('ascii'))
                    Config().update_option('access_token', creds['Token'].encode('ascii'))
                else:
                    raise IOError
            else:
                raise IOError
        except:
            raise

    def role_refresh(self):
        if self._access_token_refresh:
            try:
                self.role_config()
            except:
                warning("Could not refresh role")

    def env_config(self):
        cred_content = ""
        try:
            cred_file = open(os.environ['AWS_CREDENTIAL_FILE'],'r')
            cred_content = cred_file.read()
        except IOError as e:
            debug("Error %d accessing credentials file %s" % (e.errno,os.environ['AWS_CREDENTIAL_FILE']))
        r_data = re.compile("^\s*(?P<orig_key>\w+)\s*=\s*(?P<value>.*)")
        r_quotes = re.compile("^\"(.*)\"\s*$")
        if len(cred_content)>0:
            for line in cred_content.splitlines():
                is_data = r_data.match(line)
                if is_data:
                    data = is_data.groupdict()
                    if r_quotes.match(data["value"]):
                        data["value"] = data["value"][1:-1]
                    if data["orig_key"] == "AWSAccessKeyId" \
                       or data["orig_key"] == "aws_access_key_id":
                        data["key"] = "access_key"
                    elif data["orig_key"]=="AWSSecretKey" \
                       or data["orig_key"]=="aws_secret_access_key":
                        data["key"] = "secret_key"
                    else:
                        debug("env_config: key = %r will be ignored", data["orig_key"])

                    if "key" in data:
                        Config().update_option(data["key"], data["value"])
                        if data["key"] in ("access_key", "secret_key", "gpg_passphrase"):
                            print_value = ("%s...%d_chars...%s") % (data["value"][:2], len(data["value"]) - 3, data["value"][-1:])
                        else:
                            print_value = data["value"]
                        debug("env_Config: %s->%s" % (data["key"], print_value))

    def option_list(self):
        retval = []
        for option in dir(self):
            ## Skip attributes that start with underscore or are not string, int or bool
            option_type = type(getattr(Config, option))
            if option.startswith("_") or \
               not (option_type in (
                    type("string"), # str
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
                (key, value) = option.split(':')
                self.extra_headers[key.replace('_', '-').strip()] = value.strip()

        self._parsed_files.append(configfile)

    def dump_config(self, stream):
        ConfigDumper(stream).dump("default", self)

    def update_option(self, option, value):
        if value is None:
            return

        #### Handle environment reference
        if str(value).startswith("$"):
            return self.update_option(option, os.getenv(str(value)[1:]))

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
                    error("Config: verbosity level '%s' is not valid" % value)
                    return

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
            except:
                error("Config: value of option %s must have suffix m, k, or nothing, not '%s'" % (option, value))
                return

        ## allow yes/no, true/false, on/off and 1/0 for boolean options
        elif type(getattr(Config, option)) is type(True):   # bool
            if str(value).lower() in ("true", "yes", "on", "1"):
                value = True
            elif str(value).lower() in ("false", "no", "off", "0"):
                value = False
            else:
                error("Config: value of option '%s' must be Yes or No, not '%s'" % (option, value))
                return

        elif type(getattr(Config, option)) is type(42):     # int
            try:
                value = int(value)
            except ValueError:
                error("Config: value of option '%s' must be an integer, not '%s'" % (option, value))
                return

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
        f = open(file, "r")
        r_comment = re.compile("^\s*#.*")
        r_empty = re.compile("^\s*$")
        r_section = re.compile("^\[([^\]]+)\]")
        r_data = re.compile("^\s*(?P<key>\w+)\s*=\s*(?P<value>.*)")
        r_quotes = re.compile("^\"(.*)\"\s*$")
        for line in f:
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
        self.stream.write("[%s]\n" % section)
        for option in config.option_list():
            value = getattr(config, option)
            if option == "verbosity":
                # we turn level numbers back into strings if possible
                if isinstance(value,int) and value in logging._levelNames:
                    value = logging._levelNames[value]

            self.stream.write("%s = %s\n" % (option, value))

# vim:et:ts=4:sts=4:ai
