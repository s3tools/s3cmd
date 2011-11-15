## Amazon S3 manager - Exceptions library
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import cPickle
import os

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
        if os.getenv("HOME"):
            metadata_file = os.path.join(os.getenv("HOME"), ".s3metadata")
            if os.path.exists(metadata_file):
                self.metadata = cPickle.load(open(metadata_file, 'rb'))
        elif os.name == "nt" and os.getenv("USERPROFILE"):
            metadata_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), "Application Data", "s3metadata.ini")
            if os.path.exists(metadata_file):
                self.metadata = cPickle.load(open(metadata_file, 'rb'))


    def save(self):
        if os.getenv("HOME"):
            metadata_file = os.path.join(os.getenv("HOME"), ".s3metadata")
            cPickle.dump(self.metadata, open(metadata_file, 'wb'))
        elif os.name == "nt" and os.getenv("USERPROFILE"):
            metadata_file = os.path.join(os.getenv("USERPROFILE").decode('mbcs'), "Application Data", "s3metadata.ini")
            cPickle.dump(self.metadata, open(metadata_file, 'wb'))

# vim:et:ts=4:sts=4:ai
