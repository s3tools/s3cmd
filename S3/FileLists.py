## Create and compare lists of files/objects
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

from S3 import S3
from Config import Config
from S3Uri import S3Uri
from SortedDict import SortedDict
from Utils import *

from logging import debug, info, warning, error

import os
import glob

__all__ = ["fetch_local_list", "fetch_remote_list", "compare_filelists", "filter_exclude_include"]

def _fswalk_follow_symlinks(path):
        '''
        Walk filesystem, following symbolic links (but without recursion), on python2.4 and later

        If a recursive directory link is detected, emit a warning and skip.
        '''
        assert os.path.isdir(path) # only designed for directory argument
        walkdirs = set([path])
        targets = set()
        for dirpath, dirnames, filenames in os.walk(path):
                for dirname in dirnames:
                        current = os.path.join(dirpath, dirname)
                        target = os.path.realpath(current)
                        if os.path.islink(current):
                                if target in targets:
                                        warning("Skipping recursively symlinked directory %s" % dirname)
                                else:
                                        walkdirs.add(current)
                        targets.add(target)
        for walkdir in walkdirs:
                for value in os.walk(walkdir):
                        yield value

def _fswalk(path, follow_symlinks):
        '''
        Directory tree generator

        path (str) is the root of the directory tree to walk

        follow_symlinks (bool) indicates whether to descend into symbolically linked directories
        '''
        if follow_symlinks:
                return _fswalk_follow_symlinks(path)
        return os.walk(path)

def filter_exclude_include(src_list):
    info(u"Applying --exclude/--include")
    cfg = Config()
    exclude_list = SortedDict(ignore_case = False)
    for file in src_list.keys():
        debug(u"CHECK: %s" % file)
        excluded = False
        for r in cfg.exclude:
            if r.search(file):
                excluded = True
                debug(u"EXCL-MATCH: '%s'" % (cfg.debug_exclude[r]))
                break
        if excluded:
            ## No need to check for --include if not excluded
            for r in cfg.include:
                if r.search(file):
                    excluded = False
                    debug(u"INCL-MATCH: '%s'" % (cfg.debug_include[r]))
                    break
        if excluded:
            ## Still excluded - ok, action it
            debug(u"EXCLUDE: %s" % file)
            exclude_list[file] = src_list[file]
            del(src_list[file])
            continue
        else:
            debug(u"PASS: %s" % (file))
    return src_list, exclude_list

def fetch_local_list(args, recursive = None):
    def _get_filelist_local(local_uri):
        info(u"Compiling list of local files...")
        if local_uri.isdir():
            local_base = deunicodise(local_uri.basename())
            local_path = deunicodise(local_uri.path())
            filelist = _fswalk(local_path, cfg.follow_symlinks)
            single_file = False
        else:
            local_base = ""
            local_path = deunicodise(local_uri.dirname())
            filelist = [( local_path, [], [deunicodise(local_uri.basename())] )]
            single_file = True
        loc_list = SortedDict(ignore_case = False)
        for root, dirs, files in filelist:
            rel_root = root.replace(local_path, local_base, 1)
            for f in files:
                full_name = os.path.join(root, f)
                if not os.path.isfile(full_name):
                    continue
                if os.path.islink(full_name):
                                    if not cfg.follow_symlinks:
                                            continue
                relative_file = unicodise(os.path.join(rel_root, f))
                if os.path.sep != "/":
                    # Convert non-unix dir separators to '/'
                    relative_file = "/".join(relative_file.split(os.path.sep))
                if cfg.urlencoding_mode == "normal":
                    relative_file = replace_nonprintables(relative_file)
                if relative_file.startswith('./'):
                    relative_file = relative_file[2:]
                sr = os.stat_result(os.lstat(full_name))
                loc_list[relative_file] = {
                    'full_name_unicode' : unicodise(full_name),
                    'full_name' : full_name,
                    'size' : sr.st_size,
                    'mtime' : sr.st_mtime,
                    ## TODO: Possibly more to save here...
                }
        return loc_list, single_file

    cfg = Config()
    local_uris = []
    local_list = SortedDict(ignore_case = False)
    single_file = False

    if type(args) not in (list, tuple):
        args = [args]

    if recursive == None:
        recursive = cfg.recursive

    for arg in args:
        uri = S3Uri(arg)
        if not uri.type == 'file':
            raise ParameterError("Expecting filename or directory instead of: %s" % arg)
        if uri.isdir() and not recursive:
            raise ParameterError("Use --recursive to upload a directory: %s" % arg)
        local_uris.append(uri)

    for uri in local_uris:
        list_for_uri, single_file = _get_filelist_local(uri)
        local_list.update(list_for_uri)

    ## Single file is True if and only if the user
    ## specified one local URI and that URI represents
    ## a FILE. Ie it is False if the URI was of a DIR
    ## and that dir contained only one FILE. That's not
    ## a case of single_file==True.
    if len(local_list) > 1:
        single_file = False

    return local_list, single_file

def fetch_remote_list(args, require_attribs = False, recursive = None):
    def _get_filelist_remote(remote_uri, recursive = True):
        ## If remote_uri ends with '/' then all remote files will have
        ## the remote_uri prefix removed in the relative path.
        ## If, on the other hand, the remote_uri ends with something else
        ## (probably alphanumeric symbol) we'll use the last path part
        ## in the relative path.
        ##
        ## Complicated, eh? See an example:
        ## _get_filelist_remote("s3://bckt/abc/def") may yield:
        ## { 'def/file1.jpg' : {}, 'def/xyz/blah.txt' : {} }
        ## _get_filelist_remote("s3://bckt/abc/def/") will yield:
        ## { 'file1.jpg' : {}, 'xyz/blah.txt' : {} }
        ## Furthermore a prefix-magic can restrict the return list:
        ## _get_filelist_remote("s3://bckt/abc/def/x") yields:
        ## { 'xyz/blah.txt' : {} }

        info(u"Retrieving list of remote files for %s ..." % remote_uri)

        s3 = S3(Config())
        response = s3.bucket_list(remote_uri.bucket(), prefix = remote_uri.object(), recursive = recursive)

        rem_base_original = rem_base = remote_uri.object()
        remote_uri_original = remote_uri
        if rem_base != '' and rem_base[-1] != '/':
            rem_base = rem_base[:rem_base.rfind('/')+1]
            remote_uri = S3Uri("s3://%s/%s" % (remote_uri.bucket(), rem_base))
        rem_base_len = len(rem_base)
        rem_list = SortedDict(ignore_case = False)
        break_now = False
        for object in response['list']:
            if object['Key'] == rem_base_original and object['Key'][-1] != os.path.sep:
                ## We asked for one file and we got that file :-)
                key = os.path.basename(object['Key'])
                object_uri_str = remote_uri_original.uri()
                break_now = True
                rem_list = {}   ## Remove whatever has already been put to rem_list
            else:
                key = object['Key'][rem_base_len:]      ## Beware - this may be '' if object['Key']==rem_base !!
                object_uri_str = remote_uri.uri() + key
            rem_list[key] = {
                'size' : int(object['Size']),
                'timestamp' : dateS3toUnix(object['LastModified']), ## Sadly it's upload time, not our lastmod time :-(
                'md5' : object['ETag'][1:-1],
                'object_key' : object['Key'],
                'object_uri_str' : object_uri_str,
                'base_uri' : remote_uri,
            }
            if break_now:
                break
        return rem_list

    cfg = Config()
    remote_uris = []
    remote_list = SortedDict(ignore_case = False)

    if type(args) not in (list, tuple):
        args = [args]

    if recursive == None:
        recursive = cfg.recursive

    for arg in args:
        uri = S3Uri(arg)
        if not uri.type == 's3':
            raise ParameterError("Expecting S3 URI instead of '%s'" % arg)
        remote_uris.append(uri)

    if recursive:
        for uri in remote_uris:
            objectlist = _get_filelist_remote(uri)
            for key in objectlist:
                remote_list[key] = objectlist[key]
    else:
        for uri in remote_uris:
            uri_str = str(uri)
            ## Wildcards used in remote URI?
            ## If yes we'll need a bucket listing...
            if uri_str.find('*') > -1 or uri_str.find('?') > -1:
                first_wildcard = uri_str.find('*')
                first_questionmark = uri_str.find('?')
                if first_questionmark > -1 and first_questionmark < first_wildcard:
                    first_wildcard = first_questionmark
                prefix = uri_str[:first_wildcard]
                rest = uri_str[first_wildcard+1:]
                ## Only request recursive listing if the 'rest' of the URI,
                ## i.e. the part after first wildcard, contains '/'
                need_recursion = rest.find('/') > -1
                objectlist = _get_filelist_remote(S3Uri(prefix), recursive = need_recursion)
                for key in objectlist:
                    ## Check whether the 'key' matches the requested wildcards
                    if glob.fnmatch.fnmatch(objectlist[key]['object_uri_str'], uri_str):
                        remote_list[key] = objectlist[key]
            else:
                ## No wildcards - simply append the given URI to the list
                key = os.path.basename(uri.object())
                if not key:
                    raise ParameterError(u"Expecting S3 URI with a filename or --recursive: %s" % uri.uri())
                remote_item = {
                    'base_uri': uri,
                    'object_uri_str': unicode(uri),
                    'object_key': uri.object()
                }
                if require_attribs:
                    response = S3(cfg).object_info(uri)
                    remote_item.update({
                    'size': int(response['headers']['content-length']),
                    'md5': response['headers']['etag'].strip('"\''),
                    'timestamp' : dateRFC822toUnix(response['headers']['date'])
                    })
                remote_list[key] = remote_item
    return remote_list

def compare_filelists(src_list, dst_list, src_remote, dst_remote):
    def __direction_str(is_remote):
        return is_remote and "remote" or "local"

    # We don't support local->local sync, use 'rsync' or something like that instead ;-)
    assert(not(src_remote == False and dst_remote == False))

    info(u"Verifying attributes...")
    cfg = Config()
    exists_list = SortedDict(ignore_case = False)

    debug("Comparing filelists (direction: %s -> %s)" % (__direction_str(src_remote), __direction_str(dst_remote)))
    debug("src_list.keys: %s" % src_list.keys())
    debug("dst_list.keys: %s" % dst_list.keys())

    for file in src_list.keys():
        debug(u"CHECK: %s" % file)
        if dst_list.has_key(file):
            ## Was --skip-existing requested?
            if cfg.skip_existing:
                debug(u"IGNR: %s (used --skip-existing)" % (file))
                exists_list[file] = src_list[file]
                del(src_list[file])
                ## Remove from destination-list, all that is left there will be deleted
                del(dst_list[file])
                continue

            attribs_match = True
            ## Check size first
            if 'size' in cfg.sync_checks and dst_list[file]['size'] != src_list[file]['size']:
                debug(u"XFER: %s (size mismatch: src=%s dst=%s)" % (file, src_list[file]['size'], dst_list[file]['size']))
                attribs_match = False

            if attribs_match and 'md5' in cfg.sync_checks:
                ## ... same size, check MD5
                try:
                    if src_remote == False and dst_remote == True:
                        src_md5 = hash_file_md5(src_list[file]['full_name'])
                        dst_md5 = dst_list[file]['md5']
                    elif src_remote == True and dst_remote == False:
                        src_md5 = src_list[file]['md5']
                        dst_md5 = hash_file_md5(dst_list[file]['full_name'])
                    elif src_remote == True and dst_remote == True:
                        src_md5 = src_list[file]['md5']
                        dst_md5 = dst_list[file]['md5']
                except (IOError,OSError), e:
                    # MD5 sum verification failed - ignore that file altogether
                    debug(u"IGNR: %s (disappeared)" % (file))
                    warning(u"%s: file disappeared, ignoring." % (file))
                    del(src_list[file])
                    del(dst_list[file])
                    continue

                if src_md5 != dst_md5:
                    ## Checksums are different.
                    attribs_match = False
                    debug(u"XFER: %s (md5 mismatch: src=%s dst=%s)" % (file, src_md5, dst_md5))

            if attribs_match:
                ## Remove from source-list, all that is left there will be transferred
                debug(u"IGNR: %s (transfer not needed)" % file)
                exists_list[file] = src_list[file]
                del(src_list[file])

            ## Remove from destination-list, all that is left there will be deleted
            del(dst_list[file])

    return src_list, dst_list, exists_list

# vim:et:ts=4:sts=4:ai
