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

class BidirMap(object):
    def __init__(self, **map):
        self.k2v = {}
        self.v2k = {}
        for key in map:
            self.__setitem__(key, map[key])

    def __setitem__(self, key, value):
        if value in self.v2k:
            if self.v2k[value] != key:
                raise KeyError("Value '"+str(value)+"' already in use with key '"+str(self.v2k[value])+"'")
        try:
            del(self.v2k[self.k2v[key]])
        except KeyError:
            pass
        self.k2v[key] = value
        self.v2k[value] = key

    def __getitem__(self, key):
        return self.k2v[key]

    def __str__(self):
        return self.v2k.__str__()

    def getkey(self, value):
        return self.v2k[value]

    def getvalue(self, key):
        return self.k2v[key]

    def keys(self):
        return [key for key in self.k2v]

    def values(self):
        return [value for value in self.v2k]

# vim:et:ts=4:sts=4:ai
