## Amazon S3 manager - Exceptions library
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import cPickle
import os
from logging import debug, info, warning, error

class MetaData(object):
    _instance = None
    metadata = {}
    metadata['md5_trans'] = {}

    ## Creating a singleton
    def __new__(self):
        if self._instance is None:
            self._instance = object.__new__(self)
        return self._instance

    def __init__(self):
        metadata_file = ".s3metadata"
        if os.getenv("HOME"):
            metadata_file = os.path.join(os.getenv("HOME"), ".s3metadata")
        elif os.name == "nt" and os.getenv("USERPROFILE"):
            metadata_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), "Application Data", "s3metadata.ini")

        debug(u"Loading metadata from %s" % metadata_file)

        if os.path.exists(metadata_file):
            self.metadata = cPickle.load(open(metadata_file, 'rb'))


    def save(self):
        metadata_file = ".s3metadata"
        if os.getenv("HOME"):
            metadata_file = os.path.join(os.getenv("HOME"), ".s3metadata")
        elif os.name == "nt" and os.getenv("USERPROFILE"):
            metadata_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), "Application Data", "s3metadata.ini")

        debug(u"Saving metadata to %s" % metadata_file)
        try:
            cPickle.dump(self.metadata, open(metadata_file, 'wb'), -1)
        except IOError, e:
            error(u"Can't write out metadata file to %s: %s" % (metadata_file, e.strerror))

# vim:et:ts=4:sts=4:ai
